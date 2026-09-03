<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PostdeployCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PostdeployContext;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * A CHECK constraint that is in the catalog and is not enforced — a guarantee that is not one.
 *
 * ## Why this is worse than a constraint that is simply absent
 *
 * An absent constraint is visibly absent. `ENFORCED = NO` is a constraint that appears in
 * `SHOW CREATE TABLE`, appears in the migration that added it, appears in code review — and admits
 * every row it claims to refuse. Somebody looking for the guarantee finds it, and it is not there.
 *
 * **Measured on MySQL 8.4.10, and the measurement is the reason this check exists:**
 *
 * ```
 * SELECT CONSTRAINT_NAME, CHECK_CLAUSE FROM information_schema.CHECK_CONSTRAINTS;
 *   qty_positive   (`qty` > 0)
 *   qty_lax        (`qty` > 0)      <- NOT ENFORCED, and this view cannot tell you
 * ```
 *
 * The view that holds the EXPRESSION does not hold the flag. Only
 * `information_schema.TABLE_CONSTRAINTS.ENFORCED` does, which is why this check joins the two rather
 * than reading the obvious one — and why a person checking by hand so often concludes the constraint
 * is fine.
 *
 * ## It detects and reports, and deliberately does nothing else
 *
 * No ledger is read or written, no age is computed, no severity is escalated. Whether an unenforced
 * constraint is DEBT — how old, how bad, whether it fails a run — belongs to the debt reconciliation,
 * and building a second opinion here would give one database two answers depending on which part
 * asked.
 *
 * What the finding does carry is the full object identity — schema, table, constraint, expression —
 * so that reconciliation can resolve it without a second query.
 *
 * ## Why the remedy is not a formality
 *
 * `ALTER TABLE t ALTER CHECK c ENFORCED` re-validates against the rows already in the table, and on
 * a table that has been running unenforced it can simply fail. That is the honest reason it is a
 * proposal: the constraint was probably switched off because the data did not satisfy it, and
 * turning it back on is a data decision rather than a schema one.
 */
final readonly class UnenforcedConstraintCheck implements PostdeployCheck
{
    public const string ID = 'DEPLOY.LEGACY.CONSTRAINT_NOT_ENFORCED';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'mysql';
    }

    #[RawSql(reason: 'joins information_schema.TABLE_CONSTRAINTS and CHECK_CONSTRAINTS; the ENFORCED flag lives on one view and the expression on the other, and neither has another representation')]
    public function run(PostdeployContext $context): CheckResult
    {
        try {
            $rows = $context->session->read(static fn (Connection $db): array => $db->select(
                'select tc.CONSTRAINT_SCHEMA as schema_name, tc.TABLE_NAME as table_name,'
                .' tc.CONSTRAINT_NAME as constraint_name, cc.CHECK_CLAUSE as expression'
                .' from information_schema.TABLE_CONSTRAINTS tc'
                // LEFT, not INNER: a row whose expression cannot be read is still an unenforced
                // constraint, and dropping it would turn a partial reading into a clean result.
                .' left join information_schema.CHECK_CONSTRAINTS cc'
                .'   on cc.CONSTRAINT_SCHEMA = tc.CONSTRAINT_SCHEMA'
                .'  and cc.CONSTRAINT_NAME = tc.CONSTRAINT_NAME'
                .' where tc.CONSTRAINT_TYPE = \'CHECK\''
                .'   and tc.ENFORCED = \'NO\''
                .'   and tc.CONSTRAINT_SCHEMA not in (\'mysql\', \'information_schema\', \'performance_schema\', \'sys\')'
                .' order by tc.CONSTRAINT_SCHEMA, tc.TABLE_NAME, tc.CONSTRAINT_NAME',
            ));
        } catch (Throwable $failure) {
            // Undetermined, never a pass — and here that distinction is at its sharpest. Reporting a
            // clean result would confirm a guarantee nobody checked, which is the one failure mode
            // this check exists to prevent.
            return CheckResult::undetermined(
                self::ID,
                'the constraint catalog could not be read, so whether a CHECK constraint is standing '
                .'unenforced is unknown — and an unchecked guarantee reads exactly like a kept one: '
                .$failure->getMessage(),
            );
        }

        $findings = [];

        foreach (array_map(static fn (mixed $row): object => (object) $row, $rows) as $row) {
            $constraint = $this->text($row, 'constraint_name');

            if ($constraint === '') {
                continue;
            }

            $findings[] = $this->finding(
                $context,
                $this->text($row, 'schema_name'),
                $this->text($row, 'table_name'),
                $constraint,
                $this->text($row, 'expression'),
            );
        }

        // A FAILURE, unlike its two neighbors. The name-based checks are undetermined because a name
        // proves nothing; `ENFORCED = NO` is a fact the catalog states outright, with no second
        // reading needed and no in-flight state that looks the same. Reporting a decided fact as
        // undetermined would spend the three-valued contract on something that IS decided.
        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    private function finding(PostdeployContext $context, string $schema, string $table, string $constraint, string $expression): Finding
    {
        $qualifiedTable = $schema === '' ? $table : $schema.'.'.$table;
        $qualified = $qualifiedTable === '' ? $constraint : $qualifiedTable.'.'.$constraint;

        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The CHECK constraint `%s` on `%s` is NOT ENFORCED%s. It is in the catalog, it shows '
                .'up in SHOW CREATE TABLE, and it admits every row it claims to refuse — so somebody '
                .'looking for that guarantee finds it and it is not there. Worse, the view that holds '
                .'the expression does not hold the flag: reading '
                .'information_schema.CHECK_CONSTRAINTS shows an enforced and an unenforced '
                .'constraint identically. Turning it on is `ALTER TABLE %s ALTER CHECK %s ENFORCED;` '
                .'— a PROPOSAL, not an instruction, and not a formality: that statement re-validates '
                .'against the rows already there and can simply fail, because the likely reason it '
                .'was switched off is that the data did not satisfy it. SQLens never runs it.',
                $constraint,
                $qualifiedTable === '' ? 'its table' : $qualifiedTable,
                $expression === '' ? '' : ' — its expression is `'.$expression.'`',
                $qualifiedTable === '' ? 'the table' : $qualifiedTable,
                $constraint,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $qualified, SchemaObjectType::Constraint),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            // Medium: a guarantee that is not kept is worth acting on, and it is not a stopped
            // deploy. The debt reconciliation is what raises it as it ages — that judgment is
            // deliberately not made here.
            severity: Severity::Medium,
        )->withDowntimeClass(
            // Online: nothing about reporting it takes a lock, and the ALTER that would fix it is a
            // metadata change plus a validation pass — priced where that operation is priced, not
            // here.
            DowntimeClass::Online,
        );
    }

    /** A column of a driver row as a string — the same normalization every catalog check here makes. */
    private function text(object $row, string $column): string
    {
        $value = $row->{$column} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }
}
