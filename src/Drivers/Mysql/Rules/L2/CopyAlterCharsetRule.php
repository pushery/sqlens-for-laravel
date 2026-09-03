<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\Remediation\CharsetMigrationTemplate;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * `ALTER TABLE … CONVERT TO CHARACTER SET …` — the second great COPY trigger in InnoDB, and the
 * one a late move to `utf8mb4` walks straight into.
 *
 * It re-encodes every value in every string column, so the table is copied row by row under a
 * shared lock: writes queue for the whole run, and the run's length grows with the table. On the
 * legacy `latin1` table that has been accumulating rows for years — precisely the table anyone
 * runs this on — it is an outage.
 *
 * ## The distinction that decides everything, measured on MySQL 8.4
 *
 * The statement that converts and the statement that merely sets a default look nearly identical,
 * and their costs are nothing alike. Each of these was run under `ALGORITHM=INSTANT` and then
 * `ALGORITHM=INPLACE` against a real 8.4 to see which the server accepts:
 *
 * | Statement | MySQL 8.4 runs it | Existing rows |
 * |---|---|---|
 * | `CONVERT TO CHARACTER SET utf8mb4` | COPY | re-encoded |
 * | `DEFAULT CHARACTER SET utf8mb4` | INPLACE | **untouched** — verified: a `latin1` column stays `latin1` |
 * | `DEFAULT COLLATE …` | INPLACE | untouched |
 *
 * So a table default is a statement about FUTURE columns and nothing else, and this rule stays
 * silent on it. That silence is the rule's main false-positive defense, not an oversight: flagging
 * the cheap statement that looks like the expensive one is how a linter teaches people to ignore
 * it.
 *
 * ## Where the boundary to the column rule runs
 *
 * A column's charset can also change through `MODIFY`/`CHANGE`, and that form belongs to
 * {@see CopyAlterTypeRule} — it owns column redefinitions whole. Reporting it here as well would
 * put two findings on one statement, and two rules describing one statement is how a report starts
 * contradicting itself. The column path is covered, just not from here.
 *
 * ## Why this rule is deterministic where its sibling is heuristic
 *
 * It keeps the family default rather than overriding it, and the reason is worth stating: a column
 * redefinition names a target and hides the source, so "does this change anything" is an inference.
 * `CONVERT TO CHARACTER SET` hides nothing — it re-encodes every row whatever the current character
 * set is, including a conversion to the one already in place. The statement IS the operation.
 */
final class CopyAlterCharsetRule extends AbstractMysqlRule implements DeclaresOperationClass, DerivesDowntimeClass, ProvidesRemediation
{
    /** What a conversion costs, as the matrix keys it. */
    private const string OPERATION = 'convert_to_character_set';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The staged conversion this rule hands over, built once. */
    private readonly CharsetMigrationTemplate $template;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->template = new CharsetMigrationTemplate;
    }

    /**
     * The staged conversion — which opens with a CHECK rather than with the statement.
     *
     * The class it carries is the one this rule DERIVED for the same statement, not a constant:
     * this rule implements {@see DerivesDowntimeClass}, so the collector stamps the derived answer
     * onto the finding, and a payload reaching elsewhere would make the two disagree about one
     * statement.
     */
    #[Override]
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $this->convertsCharacterSet($statement)) {
            return null;
        }

        $context = [];

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->payload($context, $this->id(), $this->downtimeClassFor($statement));
    }

    public function id(): string
    {
        return 'MY.L2.COPY_ALTER_CHARSET';
    }

    /**
     * A charset conversion re-encodes every string in the table, which MySQL can only do by copying it.
     * Same cost shape as the type change beside it, and the reason both name one class.
     */
    public function operationClass(): string
    {
        return 'rewrite';
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /** From the matrix, for the one operation this rule is about — never named in this file. */
    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        if (! $this->convertsCharacterSet($statement)) {
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
        return $this->convertsCharacterSet($statement) ? $this->message() : null;
    }

    /**
     * Whether this statement CONVERTS the table's character set.
     *
     * These statements reach a rule unclassified — the classifier has no signature for them yet —
     * so the canonical form is what identifies them. That is safe here in a way a text match
     * usually is not: `CONVERT TO CHARACTER SET` is three folded keywords in a fixed order, which
     * is a canonical fact rather than a quirk of Laravel's formatting. The table target IS
     * classified, and requiring it keeps the match anchored to a real ALTER TABLE.
     *
     * String literals are masked first, so a default or an inserted value that happens to spell
     * the clause cannot conjure a finding out of data.
     */
    private function convertsCharacterSet(MigrationStatementView $statement): bool
    {
        if (! $statement->soleTarget(SchemaObjectType::Table) instanceof StatementTarget) {
            return false;
        }

        $masked = preg_replace("/'(?:[^']|'')*'/", "''", $statement->canonical) ?? $statement->canonical;

        return preg_match('/^ALTER TABLE \S+ .*\bCONVERT TO CHARACTER SET\b/', $masked) === 1;
    }

    private function message(): string
    {
        return 'CONVERT TO CHARACTER SET re-encodes every value in every string column, so InnoDB copies the whole '
            .'table row by row under a shared lock: writes queue for the entire run, and the run grows with the '
            .'table. The tables people run this on are the old ones, which is exactly where it hurts most. Take a '
            .'real maintenance window for it, or convert column by column so each statement covers less data and '
            .'the work can be spread over several deploys — and issue it as a raw statement carrying LOCK=NONE if '
            .'the table must stay writable, so MySQL refuses rather than silently locking it. Setting the table\'s '
            .'DEFAULT character set is a different statement: it applies to future columns only, leaves existing '
            .'rows untouched, and is not reported.';
    }
}
