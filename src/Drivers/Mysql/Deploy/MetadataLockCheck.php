<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Catalog\Activity\ActivityRequest;
use Pushery\SQLens\Catalog\Activity\ActivitySnapshot;
use Pushery\SQLens\Catalog\Activity\LongRunningSession;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\ActivityReader;
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
 * What is holding a metadata lock on the tables this deploy is about to alter.
 *
 * InnoDB's online DDL is "online" in the middle and not at the ends: it needs a brief EXCLUSIVE
 * metadata lock to start and another to finish. A transaction open on the target table blocks
 * exactly that moment — and while the ALTER waits for its MDL, every new statement touching that
 * table queues behind it. The table stops answering, and the ALTER itself is doing nothing wrong.
 *
 * ## Why silence has to be earned here more than anywhere else
 *
 * `performance_schema` can be off, and its `metadata_locks` instrument is disabled by default in
 * several distributions. Both produce an EMPTY reading, not an error — so "no blocker" and "the
 * instrument that would have told me is switched off" arrive as the same answer.
 *
 * That is why this check consults {@see ActivitySnapshot::silenceIsTrustworthy()} before reporting a
 * clean result. An empty snapshot with a named gap is `undetermined`; an empty snapshot with no gaps
 * is a pass. The distinction is the whole check.
 *
 * @see https://dev.mysql.com/doc/refman/8.4/en/performance-schema-metadata-locks-table.html
 * @see https://dev.mysql.com/doc/refman/8.4/en/innodb-online-ddl-operations.html
 */
final readonly class MetadataLockCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.METADATA_LOCK_BLOCKER';

    /**
     * The statement kinds that take an exclusive metadata lock at their boundaries.
     *
     * Every schema change does, including the ones InnoDB performs in place: the "online" part is
     * the middle, and the two ends are exclusive whatever the algorithm.
     */
    private const array SCHEMA_CHANGE_KINDS = [
        StatementKind::AlterTable,
        StatementKind::DropTable,
        StatementKind::TruncateTable,
        StatementKind::AddColumn,
        StatementKind::AlterColumn,
        StatementKind::DropColumn,
        StatementKind::AddConstraint,
        StatementKind::AddPrimaryKey,
        StatementKind::AddForeignKey,
        StatementKind::DropConstraint,
        StatementKind::CreateIndex,
        StatementKind::DropIndex,
        StatementKind::Rename,
    ];

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'mysql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        if ($context->pending->isEmpty()) {
            return CheckResult::pass(self::ID);
        }

        if (! $context->activity instanceof ActivityReader) {
            return CheckResult::undetermined(
                self::ID,
                'performance_schema_unavailable: this run has no activity reader, so what is holding '
                .'a metadata lock on the tables this migration will alter is unknown. That is not '
                .'the same as nothing holding one.',
            );
        }

        $targets = $this->schemaChangeTargets($context);

        try {
            // The targets go IN, and that is what makes the branch below reachable. `relation` on a
            // long runner is filled only for tables the caller named — `INNODB_TRX` carries none —
            // so a reading asked without a focus comes back with every relation null and the match
            // below can never succeed however blocked the instance is.
            $snapshot = $context->activity->read(new ActivityRequest($targets, $context->longRunningMs));
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'performance_schema_unavailable: the activity views could not be read: '.$failure->getMessage(),
            );
        }

        $findings = [];

        foreach ($snapshot->longRunningSessions as $session) {
            if ($session->relation !== null && in_array($session->relation, $targets, true)) {
                $findings[] = $this->blocker($context, $session);
            }
        }

        if ($findings !== []) {
            return CheckResult::fail(self::ID, $findings);
        }

        // Nothing found — and on MySQL that is precisely where the answer must be earned. An empty
        // reading is what a healthy server produces AND what a disabled instrument produces, and
        // only the named gaps tell them apart. Reporting a pass off the empty list would be the
        // single failure this package exists to prevent.
        if (! $snapshot->silenceIsTrustworthy()) {
            return CheckResult::undetermined(
                self::ID,
                'performance_schema_unavailable: the reading came back empty AND incomplete, so '
                .'"no blocker" cannot be told from "the instrument that would have reported one is '
                .'switched off". What was missing: '.$this->gapDetail($snapshot),
            );
        }

        return CheckResult::pass(self::ID);
    }

    /** Every gap, named — the sentence is the point, not the count. */
    private function gapDetail(ActivitySnapshot $snapshot): string
    {
        $reasons = array_map(
            static fn (CatalogSkip $skip): string => $skip->reference.' ('.$skip->reason->value.')',
            $snapshot->gaps(),
        );

        return $reasons === [] ? '(the reading did not say)' : implode('; ', $reasons);
    }

    /**
     * The tables the pending migration will take a metadata lock on.
     *
     * @return list<string>
     */
    private function schemaChangeTargets(PreflightContext $context): array
    {
        $targets = [];

        foreach ($context->pending->statements as $statement) {
            if (! in_array($statement->statementKind, self::SCHEMA_CHANGE_KINDS, true)) {
                continue;
            }

            foreach ($statement->targets ?? [] as $target) {
                // TABLES the statement ACTS ON, and both halves of that are load-bearing.
                //
                // A constraint is not a relation the activity views can report, so its name only
                // ever traveled here as dead weight. And a foreign key names a second table it
                // merely points at: PostgreSQL locks it SHARE ROW EXCLUSIVE, MySQL takes a shared
                // metadata lock on it — neither is what this check's own finding claims, and the finding says this deploy is about to CHANGE the table it names.
                // Naming it here would put a false sentence in front of a reader.
                //
                // The cost is named rather than hidden: a long transaction on the REFERENCED table
                // can still delay the statement, and this check does not look for that. Reporting
                // it needs a second, weaker claim, which is a feature and not a filter.
                if ($target->type !== SchemaObjectType::Table) {
                    continue;
                }
                if (! $target->isSubject()) {
                    continue;
                }
                $targets[] = $target->qualifiedName();
            }
        }

        return array_values(array_unique($targets));
    }

    private function blocker(PreflightContext $context, LongRunningSession $session): Finding
    {
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'Thread %s has been %s on `%s` for %.1F s, and this deploy is about to change that '
                .'table. InnoDB\'s online DDL is online in the MIDDLE and not at the ends — it needs '
                .'a brief EXCLUSIVE metadata lock to start and another to finish, and an open '
                .'transaction blocks exactly those moments. While the ALTER waits, every new '
                .'statement touching the table queues behind it. Nothing here says that thread is '
                .'wrong to be running; it says the migration is about to collide with it.',
                $session->session,
                $session->state,
                (string) $session->relation,
                $session->runningForMs / 1000,
            ),
            location: Location::inCatalog($context->driver, $context->connection, (string) $session->relation, SchemaObjectType::Table),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::High,
        )->withDowntimeClass(DowntimeClass::Blocking);
    }
}
