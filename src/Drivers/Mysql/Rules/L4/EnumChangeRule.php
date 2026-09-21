<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L4;

use Override;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\Remediation\EnumChangeTemplate;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\ColumnRedefinition;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A change to an `ENUM` (or `SET`) column's member list — the classic MySQL trap, and one whose two
 * halves point in opposite directions.
 *
 * ## Measured on MySQL 8.4, and it corrected the received wisdom
 *
 * Each change run under `ALGORITHM=INSTANT` then `ALGORITHM=INPLACE` against a real 8.4:
 *
 * | The member list changes by… | MySQL 8.4 runs it | Safe for a running app? |
 * |---|---|---|
 * | appending a member at the END | INSTANT | yes |
 * | appending across the 255→256 member boundary | COPY | yes |
 * | inserting a member in the middle | COPY | **no** |
 * | removing a member | COPY | **no** |
 * | reordering members | COPY | **no** |
 * | RESPELLING a member equivalently under its collation (`'b'`→`'B'`) | **INSTANT** | **no** |
 * | RENAMING a member to a different word (`'b'`→`'x'`) | **COPY**, and it ABORTS | **no** |
 *
 * ⚠️ THE LAST TWO ROWS WERE ONE ROW SAYING "RENAMING a member in place | INSTANT", and that was the
 * collation-equivalent special case sold as the general rule. The engine compares member names
 * positionally under the column's collation (`Field_enum::is_equal` → `compare_type_names`), so only a
 * respelling that the collation calls EQUAL is a no-op. Measured on MySQL 8.4.10 — the FLOOR server the
 * suite runs against, which on a development machine is not the one a bare `mysql` client reaches:
 * `MySqlTestCase` says so in its own docblock, "the default port is 3308 — Herd's MySQL 8.4 — never the
 * conventional 3306, which on a dev machine is often a legacy sub-floor server". A measurement taken on
 * 3306 here describes a version this package refuses to support.
 *
 *   'b' → 'B'  ALGORITHM=INSTANT   accepted
 *   'b' → 'x'  ALGORITHM=INSTANT   ERROR 1846  "Need to rebuild the table to change column type"
 *   'b' → 'x'  default algorithm   ERROR 1265  "Data truncated for column 's' at row 2"
 *
 * ⚠️ AND THE SECOND ERROR IS THE OPPOSITE OF WHAT THE RULE USED TO WARN ABOUT. A real rename is a
 * COPY, and during the copy the old member is no longer in the definition, so every row still holding
 * it truncates — under `STRICT_TRANS_TABLES`, which is in the default `sql_mode`, the `ALTER` simply
 * FAILS. The rule warned about a silent reinterpretation and said nothing about an abort.
 *
 * The respelling row is still the one nobody expects, and it is where the old text's danger really
 * lives: the stored values are ordinals, so `'b'`→`'B'` rewrites nothing and takes no lock — and every
 * row that read `'b'` a moment ago now reads `'B'`, in an application that has not been redeployed.
 * Cost and compatibility are not the same axis, and a rule that reported only the cost would call this
 * one free.
 *
 * That is why this rule sits at level 4 (backward compatibility) rather than with its
 * cost-oriented siblings at level 2: what it is about is the running application, and the table
 * rewrite is a consequence some of the cases happen to also have.
 *
 * ## The honesty boundary, same as its sibling on column types
 *
 * MySQL's `MODIFY` names the column's WHOLE definition, so the statement carries the target member
 * list and not the current one. Which of the six rows above a given statement is cannot be read
 * from it — only from a comparison with the live column. The rule is therefore
 * {@see Confidence::Heuristic}, it reports the append-only case too, and it says so in its own
 * text. The asymmetry is deliberate: a false positive costs one look at the column, a false
 * negative ships an application that reads a value the database no longer has.
 */
final class EnumChangeRule extends AbstractMysqlRule implements DerivesDowntimeClass, ProvidesRemediation
{
    /**
     * What the matrix keys this operation on.
     *
     * Its entry is CONDITIONAL — on the value being appended at the end and on the storage size
     * being unchanged — and a static reader can decide neither, so the matrix answers `undetermined`
     * and this finding carries no class. That is the arrangement working: the measurement above
     * shows the cost genuinely ranges from INSTANT to COPY, so any single class would be wrong
     * about most of the cases.
     */
    private const string OPERATION = 'modify_enum_definition';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The sequence this rule hands over, built once. */
    private readonly EnumChangeTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new EnumChangeTemplate;
    }

    /**
     * The sequence — which opens with a comparison rather than a statement.
     *
     * The class it carries is the one this rule DERIVED for the same statement, not its constant:
     * this rule implements {@see DerivesDowntimeClass}, so the collector stamps the derived answer
     * on the finding, and a payload reaching for the constant instead would make the two disagree
     * about one statement. The matrix declines this operation, so the honest value is usually null
     * — and null is what travels.
     */
    #[Override]
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->redefinesAnEnum($statement)) {
            return null;
        }

        $context = [];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->forMemberListChange($context, $this->id(), $this->downtimeClassFor($statement));
    }

    public function id(): string
    {
        return 'MY.L4.ENUM_CHANGE';
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /**
     * Heuristic, and for the same reason its sibling on column types is: the statement names the
     * target member list and hides the current one, so "this is not an append" is an inference.
     */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    /** From the matrix — which declines here, and is right to (see the OPERATION docblock). */
    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        if (! $this->redefinesAnEnum($statement)) {
            return null;
        }

        return $this->downtimeClasses->forCandidateOperations(
            [self::OPERATION],
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->downtimeClass;
    }

    #[Override]
    protected function judge(MigrationStatementView $statement): ?string
    {
        return $this->redefinesAnEnum($statement) ? $this->message() : null;
    }

    /** Whether this statement redefines an enumerated column of a table that already holds rows. */
    private function redefinesAnEnum(MigrationStatementView $statement): bool
    {
        $redefinition = ColumnRedefinition::parse($statement->canonical);

        if (! $redefinition instanceof ColumnRedefinition || ! $redefinition->isEnumerated()) {
            return false;
        }

        // A column of a table born in this migration has no rows to be incompatible with, and no
        // deployed application reading them. The same exception every column rule here carries.
        $table = $statement->soleTarget(SchemaObjectType::Table);

        return ! $table instanceof StatementTarget || ! $statement->migration->createsTable($table->qualifiedName());
    }

    private function message(): string
    {
        return 'This redefines an enumerated column\'s member list, and the statement names the whole list rather '
            .'than the change — so which kind of change it is can only be seen by comparing against the live '
            .'column. Appending a member at the end is safe and instant. Everything else is not: inserting in the '
            .'middle, removing a member and reordering all rewrite the table. RENAMING a member to a different word '
            .'rewrites it too, and on a table that still holds the old member the rewrite TRUNCATES — under the '
            .'default sql_mode the ALTER fails outright rather than running. The one genuinely instant member change '
            .'besides an append is a RESPELLING the column collation treats as equal, such as \'b\' to \'B\' under '
            .'utf8mb4_0900_ai_ci: nothing is rewritten and no lock is taken, and that is what makes it dangerous — '
            .'the stored values are ordinals, so every row that read the old spelling now reads the new one, in an '
            .'application that has not been redeployed. Append at the end, or stage the change: add the new member, '
            .'deploy the code that accepts it, migrate the rows, then remove the old one in a later release. '
            .'(An append-only change is reported here too — the statement does not say which kind it is.)';
    }
}
