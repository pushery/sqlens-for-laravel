<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
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
 * Constraints added `NOT VALID` where the `VALIDATE CONSTRAINT` never followed.
 *
 * `ADD CONSTRAINT … NOT VALID` is the SAFE way to add a foreign key or a check to a large table: it
 * takes a brief lock, applies to new rows immediately, and skips the full scan. The scan is then
 * done separately by `VALIDATE CONSTRAINT`, which takes a weaker lock and can run outside the deploy
 * window.
 *
 * That is the whole design, and it has one failure mode: the second half never happens. Nothing
 * breaks, nothing is slow, and no error is raised — the constraint simply does not hold for the rows
 * that were already there. A foreign key that everybody believes is enforced is not, and the day
 * somebody relies on it is much later than the day it stopped being true.
 *
 * ## Why the deploy gate is the right place to say so
 *
 * The debt is invisible in normal operation and expensive at exactly one moment: a rewrite of that
 * table. PostgreSQL validates a `NOT VALID` constraint as part of a rewrite, so a migration that
 * looked like a quick `ALTER` turns into a full scan nobody planned for, inside the window.
 *
 * ## Why nothing is validated here
 *
 * `VALIDATE CONSTRAINT` takes a `SHARE UPDATE EXCLUSIVE` lock and scans the whole table. Running one
 * would be a plain violation of the promise this command makes — it never takes its own locks — and
 * would turn a read-only gate into the longest step of the deploy.
 *
 * @see https://www.postgresql.org/docs/18/sql-altertable.html
 */
final readonly class NotValidConstraintCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.LEGACY.CONSTRAINT_NOT_VALIDATED';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        // PostgreSQL only. MySQL has no `NOT VALID`: a foreign key is validated when it is added or
        // it is not added at all, so there is no half-finished state to find. That is an absence of
        // the concept rather than a gap in this check, which is why there is no MySQL sibling ticket.
        return $driver === 'pgsql';
    }

    #[RawSql(reason: 'reads pg_constraint.convalidated; an unvalidated constraint is a catalog fact and the whole subject of this check')]
    public function run(PreflightContext $context): CheckResult
    {
        try {
            $rows = $context->session->read(static fn (Connection $db): array => $db->select(
                'select n.nspname as schema_name, t.relname as table_name, c.conname as constraint_name,'
                .' c.contype as constraint_type'
                .' from pg_constraint c'
                .' join pg_class t on t.oid = c.conrelid'
                .' join pg_namespace n on n.oid = t.relnamespace'
                // Extension-owned constraints are the extension's business, and a project cannot
                // act on one — reporting it asks somebody to fix what they do not own.
                .' where not exists ('
                .'   select 1 from pg_depend d'
                .'   where d.objid = c.oid and d.classid = \'pg_constraint\'::regclass and d.deptype = \'e\''
                .' )'
                .' and c.convalidated = false'
                .' order by n.nspname, t.relname, c.conname',
            ));
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'the constraint catalog could not be read, so whether this schema carries constraints '
                .'that were never validated is unknown. A `NOT VALID` constraint that nobody finished '
                .'looks exactly like one that was: '.$failure->getMessage(),
            );
        }

        $findings = [];

        // Normalized rather than guarded. A `! is_object($row)` branch here read as defensive and
        // was unreachable — the driver answers with objects, every time, and the coverage gate said
        // so by never entering it. A cast states the same requirement without a line nothing can
        // execute, and an unexecutable guard is worse than none: it looks like a check somebody made.
        // The constraints THIS deploy validates, read once. Reporting one of them as an open debt
        // would be a false positive of the worst kind for a gate: it names a problem the very run
        // being gated is about to fix, and a gate that cries wolf about work already in the queue is
        // one people learn to click past.
        $beingValidated = $this->validatedByPendingWork($context);

        foreach (array_map(static fn (mixed $row): object => (object) $row, $rows) as $row) {
            $constraint = $this->text($row, 'constraint_name');

            if (in_array($constraint, $beingValidated, true)) {
                continue;
            }

            $findings[] = $this->finding(
                $context,
                $this->text($row, 'schema_name'),
                $this->text($row, 'table_name'),
                $constraint,
                $this->text($row, 'constraint_type'),
            );
        }

        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    /**
     * The constraint names a pending `ALTER TABLE … VALIDATE CONSTRAINT` will settle.
     *
     * Read structurally rather than out of the SQL text. `ADD CONSTRAINT` and `DROP CONSTRAINT`
     * each carry their own statement kind, so an `AlterTable` that names a CONSTRAINT is the
     * validate shape — the one signature that produces that pair. A later signature which broke
     * that would have to say so where the signatures are declared, which is where somebody adding
     * one is already looking.
     *
     * Compared on the bare name, because that is what `pg_constraint` stores: a constraint is named
     * within its table, and the statement qualifies the TABLE rather than the constraint.
     *
     * @return list<string>
     */
    private function validatedByPendingWork(PreflightContext $context): array
    {
        $names = [];

        foreach ($context->pending->statements as $statement) {
            if ($statement->statementKind !== StatementKind::AlterTable) {
                continue;
            }

            foreach ($statement->targets ?? [] as $target) {
                if ($target->type === SchemaObjectType::Constraint) {
                    $names[] = $target->qualifiedName();
                }
            }
        }

        return array_values(array_unique($names));
    }

    /** One column as a string; a non-scalar becomes empty rather than a plausible wrong value. */
    private function text(object $row, string $column): string
    {
        $value = $row->{$column} ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * What this constraint type failing to hold actually means.
     *
     * Named per type rather than described generically, because the consequences are genuinely
     * different and a reader deciding what to do first needs the difference. A `NOT NULL` that does
     * not hold is the sharpest of the three: application code written against it will assume a value
     * is present, and the row where it is not was already there before anyone looked.
     */
    private function consequence(string $type): string
    {
        return match ($type) {
            'f' => 'a foreign key that everybody believes is enforced is not, for every row that '
                .'existed before it was added — so an orphaned reference can already be in the table',
            'c' => 'a check constraint that reads as a guarantee does not hold for the rows that '
                .'were already there, so code written against it can meet a value it excludes',
            'n' => 'a NOT NULL that does not hold for existing rows, which is the sharpest of these: '
                .'code written against it assumes a value is present',
            default => 'a constraint that reads as a guarantee does not hold for the rows that were '
                .'already there',
        };
    }

    private function finding(
        PreflightContext $context,
        string $schema,
        string $table,
        string $constraint,
        string $type,
    ): Finding {
        $qualified = $schema === '' ? $table : $schema.'.'.$table;

        // The finding is located on the CONSTRAINT, not on the table that holds it — and the
        // difference is not cosmetic. Findings are deduplicated on `ruleId@location->sortKey()`, so
        // while this named the table, every unvalidated constraint on one table was the same object:
        // a user with five was told about one, fixed it, ran again, and was told about the next.
        // Measured on a real server before it was fixed — three unvalidated constraints across two
        // tables reported two findings, exactly one per table.
        //
        // It also makes `objectType` and `objectName` agree at last. The invalid-index rule next
        // door names its index; this one declared `Constraint` and handed back a table, so one
        // `object_name` field meant two different things depending on which rule wrote it.
        //
        // The table is not lost: it stays in the message and in the remedy, which is where a reader
        // needs it.
        $qualifiedConstraint = $schema === '' ? $constraint : $schema.'.'.$constraint;

        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'The constraint `%s` on `%s` was added `NOT VALID` and never validated — %s. Nothing '
                .'about this is broken or slow today, which is exactly why it survives. It becomes '
                .'expensive at one moment: PostgreSQL validates a NOT VALID constraint as part of a '
                .'table REWRITE, so a migration that looked like a quick ALTER turns into a full '
                .'scan nobody planned for, inside the window. Finish it as its own short step '
                .'OUTSIDE the deploy: `ALTER TABLE %s VALIDATE CONSTRAINT %s;` — it takes a SHARE '
                .'UPDATE EXCLUSIVE lock and scans the table, which is why this command will not run '
                .'it for you.',
                $constraint,
                $qualified,
                $this->consequence($type),
                $qualified,
                $constraint,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $qualifiedConstraint, SchemaObjectType::Constraint),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            // Medium, and deliberately not higher on its own. The debt is real and it is old — a
            // finding that shouted would shout on every run of every project that ever did the safe
            // thing and got interrupted, and a gate that always shouts stops being read. What makes
            // a specific one urgent is a pending rewrite of that table, which needs the pending
            // migrations this command does not carry yet.
            severity: Severity::Medium,
        )->withDowntimeClass(
            // `online`: the unvalidated constraint locks nothing by existing. The rewrite it can
            // silently lengthen is somebody else's finding, on the statement that does the rewrite.
            DowntimeClass::Online,
        );
    }
}
