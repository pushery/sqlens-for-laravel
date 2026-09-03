<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L2;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\JudgesSchemaObjects;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\InstanceScope;
use Pushery\SQLens\Rules\Keys\TableKeyState;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An InnoDB table left without a primary key.
 *
 * On MySQL this is not a matter of schema taste. Three things break, and each of them breaks at
 * the worst possible moment:
 *
 * - **Row-based replication turns pathological.** Without a key, applying one row change on a
 *   replica means a full table scan per row, so a replica falls behind under exactly the write
 *   volume that made replication worth having.
 * - **Every online schema-change tool refuses to run.** `gh-ost` needs a shared PRIMARY or UNIQUE
 *   key to chunk by; `pt-online-schema-change` exits with `NO_PRIMARY_OR_UNIQUE_KEY`. The table
 *   that most needs an online migration is then the one that cannot have one.
 * - **The server may reject the statement outright.** `sql_require_primary_key` exists for this,
 *   and a managed provider that sets it turns the migration into a failed deploy.
 *
 * ## Level 2, deliberately, and decided rather than assumed
 *
 * The generic level table places "missing primary key" under schema basics (level 5). For MySQL
 * it sits at level 2 with the blocking-DDL core, because the three consequences above are
 * operational risk rather than style — and the audience that runs a low-downtime gate at levels
 * 0–4 is exactly the audience that must see it. Rule membership is driver-specific by design, so
 * the same condition being level 5 generically and level 2 here is the intended shape.
 *
 * ## Two statements, one condition
 *
 * A table can end up unkeyed by being born that way or by having its key removed, and both are
 * this rule's business. They are, however, very different DEPLOYS: creating a table blocks
 * nobody, while `DROP PRIMARY KEY` rebuilds the table with `ALGORITHM=COPY`. The finding's
 * downtime class therefore differs per statement, which is why this rule derives it from the
 * online-DDL matrix instead of declaring one — a single constant would be wrong about one of them.
 *
 * A `DROP PRIMARY KEY` whose migration adds a key back is not flagged: the table is keyed by the
 * time the migration ends, and reporting the intermediate state would flag the correct way to
 * REPLACE a primary key.
 *
 * ## What it deliberately does not decide
 *
 * A table created from another one, and a table with a `UNIQUE` key but no primary key, are
 * reported as undetermined rather than judged — see {@see UndeterminedReason::TableKeyUndetermined}
 * for both shapes. A deliberately keyless log or staging table is a real case and is handled the
 * way every intentional exception in this package is: with a baseline entry, a config ignore, or
 * a migration annotation — never by weakening the rule until it stops seeing the real ones.
 */
final class TableWithoutPrimaryKeyRule extends AbstractMysqlRule implements DeclaresJudgedObjectTypes, DerivesDowntimeClass, JudgesSchemaObjects, ProvidesRemediation
{
    /**
     * Tables only — a run that read none produced no subject for this rule, and the report has to be
     * able to say so rather than let the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    /** What removing a primary key costs, as the matrix keys it. */
    private const string DROP_OPERATION = 'drop_primary_key';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The considered `none` — which key to use is a schema decision, and this rule says so. */
    private readonly NoSafeSequenceTemplate $noSafeSequence;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->noSafeSequence = new NoSafeSequenceTemplate;
    }

    public function id(): string
    {
        return 'MY.L2.NO_PRIMARY_KEY';
    }

    /**
     * Both suites, because it really answers in both — and the registry export is what a reader
     * trusts to say where a finding with this id can come from.
     *
     * @return list<Suite>
     */
    #[Override]
    public function suites(): array
    {
        return [Suite::Lint, Suite::Audit];
    }

    /**
     * A table without a primary key is a fact about the SCHEMA, and a schema is the same object on
     * every node that carries the database — so this answers on a replica exactly as well as on the
     * primary.
     *
     * Stated here because this rule is the first dual-subject one: it descends from the lint base,
     * which declares the conservative `instance` scope for a family that never addresses an instance
     * at all. Inheriting that would have withheld a perfectly answerable schema finding on every
     * replica audit — and withheld it silently, since a withheld finding and a clean table produce
     * the same quiet report. Caught by the completeness guard the moment the scope existed.
     */
    #[Override]
    public function instanceScope(): InstanceScope
    {
        return InstanceScope::Database;
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /**
     * The class for THIS statement.
     *
     * A `DROP PRIMARY KEY` gets it from the matrix — that statement really does rebuild the
     * table. A `CREATE TABLE` gets NONE, and that absence is a statement of its own: creating a
     * table blocks nobody, so the class here is inapplicable rather than unknown. Attaching
     * `rewrite` because the eventual FIX rebuilds the table would tell a release gate that this
     * deploy needs a maintenance window, which is simply not true.
     */
    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        if (! $this->dropsThePrimaryKey($statement)) {
            return null;
        }

        return $this->downtimeClasses->forCandidateOperations(
            [self::DROP_OPERATION],
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->downtimeClass;
    }

    /**
     * A considered `none` — twice, because the two ways to end up keyless are not the same problem.
     *
     * On a `CREATE TABLE` the table is EMPTY. Adding the key costs nothing at all right now, and
     * everything later: the same key added to a populated table is a `COPY` ALTER. That asymmetry is
     * the whole content of the advice, and it is why this is still a `none` rather than a one-line
     * migration statement — WHICH key is a schema decision. A surrogate `id BIGINT UNSIGNED
     * AUTO_INCREMENT` is usually right and the reason says so; a linter that emitted it would be
     * choosing somebody's clustering order for them, which on InnoDB decides physical row order.
     *
     * After a `DROP PRIMARY KEY` the table has rows, and putting a key back needs a candidate that
     * is unique AND `NOT NULL` across all of them — a fact about data this package never reads. If
     * no natural candidate exists, the route is the staged swap rather than a one-liner, and the
     * reason names it rather than this rule handing over a plan for a column nobody has chosen.
     *
     * Both are silent for the undetermined verdict: a `UNIQUE` key on columns whose nullability the
     * statement does not state may or may not be promoted to the clustered key by InnoDB, and
     * material saying "you have no key" would overtake a verdict that says it does not know.
     */
    #[Override]
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $case = $this->keylessCase($statement);

        if ($case !== 'on_create' && $case !== 'after_a_drop') {
            return null;
        }

        // Written out rather than concatenated from `$case`: a translation key assembled at
        // runtime cannot be grepped, so the day one of them is renamed the search that would have
        // found it comes back empty.
        return $this->noSafeSequence->payload(
            match ($case) {
                'on_create' => 'sqlens::messages.remediation.no_safe_sequence.no_primary_key_on_create',
                default => 'sqlens::messages.remediation.no_safe_sequence.no_primary_key_after_drop',
            },
            'sqlens::messages.remediation.no_safe_sequence.schema_decision_verification',
            $this->id(),
            $this->downtimeClassFor($statement),
        );
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        return match ($this->keylessCase($statement)) {
            'after_a_drop' => RuleVerdict::flag($this->dropMessage()),
            'on_create' => RuleVerdict::flag($this->createMessage()),
            'undetermined' => RuleVerdict::undetermined(
                $this->undeterminedMessage(),
                UndeterminedReason::TableKeyUndetermined,
            ),
            default => null,
        };
    }

    /**
     * Which keyless case this statement is, if any — read ONCE, for the verdict and the material.
     *
     * The two flags carry different prose and different reason keys, so neither caller can be
     * derived from the other's answer; what they CAN share is the reading that decides which case
     * it is, and that is the copy worth not making.
     *
     * @return 'after_a_drop'|'on_create'|'undetermined'|null
     */
    private function keylessCase(MigrationStatementView $statement): ?string
    {
        if ($this->dropsThePrimaryKey($statement)) {
            return $this->keyIsRestored($statement) ? null : 'after_a_drop';
        }

        if (! $statement->is(StatementKind::CreateTable)) {
            return null;
        }

        return match (TableKeyState::inCreateTable($statement->canonical)) {
            TableKeyState::Keyed => null,
            TableKeyState::Unkeyed => 'on_create',
            TableKeyState::Undetermined => 'undetermined',
        };
    }

    /**
     * The same question, asked of a table that already exists.
     *
     * This is one rule with two subjects rather than two rules, and the id is the reason: a rule id
     * is public API from 1.0, so `MY.L2.NO_PRIMARY_KEY` has to mean one thing. A second id for the
     * same condition would make an ignore-list entry ambiguous — a project that decided its staging
     * table may stay keyless would have to remember to silence it twice, and would find out it had
     * not the next time the other suite ran.
     *
     * What the catalog adds is not a second opinion but a settled one. The migration reading
     * reports `Undetermined` for a table that declares a `UNIQUE` key and no `PRIMARY KEY`, because
     * whether InnoDB promotes that index to the clustered key turns on the columns being NOT NULL
     * and the statement does not say. The catalog does say. Both readings live in
     * {@see TableKeyState}, so the two suites cannot disagree about what "keyed" means.
     *
     * @return list<RuleVerdict>
     */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        // A partition is judged at its parent and an extension's tables are its own design — the
        // same exclusions the PostgreSQL sister applies, for the same reasons.
        if ($object->isPartition || $object->fromExtension) {
            return [];
        }

        $name = $object->getString('logical_name') ?? $object->qualifiedName;

        return match (TableKeyState::inCatalog($object)) {
            TableKeyState::Keyed => [],
            TableKeyState::Unkeyed => [RuleVerdict::flag($this->liveTableMessage($name))],
            TableKeyState::Undetermined => [RuleVerdict::undetermined(
                $this->liveUndeterminedMessage($name),
                UndeterminedReason::TableKeyUndetermined,
            )],
        };
    }

    /**
     * Whether this statement removes the table's primary key.
     *
     * `DROP PRIMARY KEY` classifies as a generic dropped constraint — the same kind a dropped
     * CHECK or a dropped named index carries — so the canonical text is what tells them apart.
     * Reading the kind alone would make this rule fire on every dropped constraint.
     */
    private function dropsThePrimaryKey(MigrationStatementView $statement): bool
    {
        return $statement->is(StatementKind::DropConstraint)
            && preg_match('/\bDROP PRIMARY KEY\b/', $statement->canonical) === 1;
    }

    /**
     * Whether the migration puts a primary key back on the same table after dropping it.
     *
     * Ordered, not merely present: a key added BEFORE the drop is the key being dropped. The
     * stream carries the statements in capture order, so "after" is a fact the rule can read
     * rather than assume.
     */
    private function keyIsRestored(MigrationStatementView $statement): bool
    {
        $table = $statement->soleTarget(SchemaObjectType::Table);

        if (! $table instanceof StatementTarget) {
            return false;
        }

        foreach ($statement->migration->statements as $other) {
            if ($other->index <= $statement->statementIndex) {
                continue;
            }
            if ($other->kind !== StatementKind::AddPrimaryKey) {
                continue;
            }
            $otherTable = $other->soleTarget(SchemaObjectType::Table);

            if ($otherTable instanceof StatementTarget && $otherTable->qualifiedName() === $table->qualifiedName()) {
                return true;
            }
        }

        return false;
    }

    private function createMessage(): string
    {
        return 'This creates an InnoDB table with no primary key, which on MySQL is an operational problem rather '
            .'than a matter of style. Row-based replication has to scan the whole table for every row it applies, so '
            .'a replica falls behind under exactly the write volume that made replication worth having; and every '
            .'online schema-change tool refuses to run without a key (gh-ost needs one to chunk by, '
            .'pt-online-schema-change exits with NO_PRIMARY_OR_UNIQUE_KEY), so the table that most needs an online '
            .'migration is the one that cannot have one. A server with sql_require_primary_key set rejects the '
            .'statement outright. Give the table a key — $table->id(), or $table->primary([…]) for a natural '
            .'composite one. Adding it later rebuilds the whole table.';
    }

    private function dropMessage(): string
    {
        return 'This removes the table\'s primary key and the migration does not put one back, leaving an InnoDB '
            .'table with no key: row-based replication scans the whole table per applied row, and every online '
            .'schema-change tool refuses to work on it. The statement itself rebuilds the table with '
            .'ALGORITHM=COPY, so it is expensive AND leaves the table worse off. If you are REPLACING the key, add '
            .'the new one in the same migration — that is recognized and reported as nothing.';
    }

    private function undeterminedMessage(): string
    {
        return 'Whether this table ends up with a usable clustered key cannot be read off the statement that creates '
            .'it. Either it takes its structure from another table, or it declares a UNIQUE key but no PRIMARY KEY — '
            .'and InnoDB promotes the first UNIQUE NOT NULL index to the clustered index, so such a table may be '
            .'perfectly keyed or not keyed at all depending on whether those columns are nullable. Check the '
            .'resulting table definition on the server. Note that sql_require_primary_key demands a real PRIMARY KEY '
            .'either way.';
    }

    private function liveTableMessage(string $table): string
    {
        return sprintf(
            '%s exists with no primary key and no UNIQUE index over NOT NULL columns that InnoDB could '
            .'promote to the clustered index. Row-based replication has to scan the whole table for every '
            .'row it applies, so a replica falls behind under exactly the write volume that made '
            .'replication worth having; and every online schema-change tool refuses to work on it — gh-ost '
            .'needs a key to chunk by, pt-online-schema-change exits with NO_PRIMARY_OR_UNIQUE_KEY — so the '
            .'table that most needs an online migration is the one that cannot have one. Adding the key now '
            .'rebuilds the table, and it only gets more expensive.',
            $table,
        );
    }

    private function liveUndeterminedMessage(string $table): string
    {
        return sprintf(
            '%s has no primary key, and whether one of its UNIQUE indexes serves as the clustered key could '
            .'not be settled: the nullability of at least one indexed column was not read. InnoDB promotes '
            .'the first UNIQUE index whose columns are all NOT NULL, so that is the fact the answer turns '
            .'on. Note that sql_require_primary_key demands a real PRIMARY KEY either way.',
            $table,
        );
    }
}
