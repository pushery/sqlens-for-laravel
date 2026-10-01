<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Catalog\Activity\ActivityRequest;
use Pushery\SQLens\Catalog\Activity\LockMode;
use Pushery\SQLens\Catalog\Activity\LongRunningSession;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\ShareUpdateExclusiveAlter;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * What is holding the locks the pending migration is about to ask for.
 *
 * An `ALTER TABLE` needs ACCESS EXCLUSIVE. A transaction that has been open on that table for
 * minutes turns the request into a QUEUE — and because PostgreSQL queues lock requests in order,
 * every read arriving behind the waiting ALTER waits too. The table stops answering while nothing
 * anywhere reports an error.
 *
 * Not every statement asks for that lock, and the report says what the statement really takes.
 * Adding a foreign key takes SHARE ROW EXCLUSIVE, which a transaction that only READ the table does
 * not delay, while one that wrote to it does; validating a constraint, like changing a maintenance
 * storage parameter such as `fillfactor`, takes SHARE UPDATE EXCLUSIVE, which no read and no write
 * delays. A `DROP INDEX` names only its index and takes ACCESS EXCLUSIVE
 * on the index's TABLE, which the catalog is asked for.
 *
 * `CREATE INDEX CONCURRENTLY` is the other shape and needs its own branch: it waits for ALL older
 * transactions to finish, not only the ones on its own table. A long analytics query on an unrelated
 * schema delays it just as effectively, which is why filtering blockers by target would report a
 * clean instance for a build that cannot start.
 *
 * ## What the finding does and does not say
 *
 * It names a session id, its age, its state and the relation. It never quotes the query text: a
 * production statement carries literals, and a report that reproduces them has moved user data into
 * a file somebody pastes into a ticket.
 *
 * It is also NOT a verdict on the blocker. A long-running analytics query is a legitimate thing for
 * a database to be doing; what the report says is that a migration is about to collide with it. The
 * threshold is the activity reader's, and it is deliberately low for a deploy — five seconds is
 * unremarkable at noon and is exactly the thing to know about in the minute before a migration.
 *
 * @see https://www.postgresql.org/docs/18/explicit-locking.html
 */
final readonly class LockBlockerCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.LOCK_BLOCKER';

    /**
     * Renamed from `…CONCURRENTLY_BLOCKER` on 2026-08-17, and the reason is architectural rather
     * than cosmetic.
     *
     * `DEPLOY.*` is the driver-NEUTRAL family, and its metadata lives in the core catalog. The core
     * may not carry engine vocabulary — `CorePurityArchTest` forbids the literal `CONCURRENTLY`
     * outside the two driver namespaces — so an id embedding that keyword could never be cataloged
     * there. It stayed uncataloged for exactly that reason and shipped a documentation link to
     * nothing.
     *
     * Renaming was free: the old spelling was in no registry, so no page resolved it and a baseline
     * naming it was already reported as unknown. The concept keeps its name in ordinary English; only
     * the SQL keyword is gone.
     */
    public const string CONCURRENTLY_ID = 'DEPLOY.PREFLIGHT.CONCURRENT_INDEX_BLOCKER';

    /**
     * The statement kinds that lock their target table, ACCESS EXCLUSIVE unless the statement itself
     * says otherwise: adding a foreign key takes SHARE ROW EXCLUSIVE, and validating a constraint or
     * changing a maintenance storage parameter SHARE UPDATE EXCLUSIVE ({@see self::lockTargets()}).
     *
     * Listed rather than derived from `downtime_class`: that axis answers what an operation costs,
     * and two operations with the same cost can take different locks. This is a claim about LOCKS.
     */
    private const array EXCLUSIVE_KINDS = [
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
        StatementKind::Rename,
    ];

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'pgsql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        // Nothing pending is not a quiet pass by accident — it is the honest one. A deploy with no
        // migrations collides with nothing, and reading the activity views to say so would spend
        // budget on a question nobody asked.
        if ($context->pending->isEmpty()) {
            return CheckResult::pass(self::ID);
        }

        if (! $context->activity instanceof ActivityReader) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::ActivityUnreadable,
                'this run has no activity reader, so what is holding locks on '
                .'the tables this migration is about to alter is unknown. That is not the same as '
                .'nothing holding them.',
            );
        }

        try {
            $targets = $this->lockTargets($context);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::ActivityUnreadable,
                'the catalog could not say which table a dropped index belongs to, so what is holding '
                .'locks on that table is unknown: '.new CredentialRedactor()->redact($failure->getMessage()),
            );
        }

        try {
            // The targets go IN, and that is what makes the branch below reachable. `relation` on a
            // long runner is filled only for relations the caller named — `pg_stat_activity` does not
            // carry one, so a reading asked without a focus comes back with every relation null and
            // the match below can never succeed however blocked the instance is.
            $snapshot = $context->activity->read(new ActivityRequest(array_map(strval(...), array_keys($targets)), $context->longRunningMs));
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::ActivityUnreadable,
                'the activity views could not be read, so what is holding locks '
                .'on the target tables is unknown: '.new CredentialRedactor()->redact($failure->getMessage()),
            );
        }

        $findings = [];

        foreach ($snapshot->longRunningSessions as $session) {
            $blocked = $this->blockedTarget($session, $targets);

            if ($blocked !== null) {
                $findings[] = $this->blocker($context, $session, $blocked, $targets[$blocked]);
            }
        }

        // The CONCURRENTLY branch, and it is separate rather than a filter on the one above for the
        // reason that makes it worth having: a concurrent build waits for EVERY older transaction,
        // including ones on tables it never touches. Reporting only the blockers on its own target
        // would call an instance clean for a build that cannot start.
        if ($this->hasConcurrentBuild($context) && $snapshot->longRunningSessions !== []) {
            $findings[] = $this->concurrentBlocker($context, count($snapshot->longRunningSessions));
        }

        if ($findings !== []) {
            return CheckResult::fail(self::ID, $findings);
        }

        // Nothing found, and the answer has to be EARNED. An activity reading that could not see
        // part of what it asked for produces the same empty list as a quiet server — so a pass off
        // the empty list alone would be the silent green this package exists to refuse. Retrofitted
        // from the MySQL sibling, where a disabled `performance_schema` instrument makes the trap
        // unmissable; the same trap exists here whenever a role may not read the activity views.
        if (! $snapshot->silenceIsTrustworthy()) {
            $gaps = array_map(
                static fn (CatalogSkip $skip): string => $skip->reference.' ('.$skip->reason->value.')',
                $snapshot->gaps(),
            );

            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::ActivityUnreadable,
                'the reading came back empty AND incomplete, so "no blocker" '
                .'cannot be told from "the view that would have reported one was withheld". What '
                .'was missing: '.($gaps === [] ? '(the reading did not say)' : implode('; ', $gaps)),
            );
        }

        return CheckResult::pass(self::ID);
    }

    /**
     * The relations the pending migration will lock, each with whether that lock stops readers too.
     *
     * Read from the statements' own `targets`, which the capture already resolved. Parsing the SQL
     * here would be a second classification that can disagree with the one the report is built on.
     * The one exception is a `DROP INDEX`: it names only its index, so its table is asked of the
     * catalog ({@see IndexTables}).
     *
     * @return array<string, bool> relation => whether the lock taken there stops reads as well as writes
     */
    private function lockTargets(PreflightContext $context): array
    {
        $targets = [];
        $droppedIndexes = [];

        foreach ($context->pending->statements as $statement) {
            if ($statement->statementKind === StatementKind::DropIndex) {
                // `DROP INDEX CONCURRENTLY` takes no lock that blocks the table, so only the plain
                // form counts.
                if (stripos($statement->canonicalSql ?? $statement->rawSql, 'concurrently') === false) {
                    foreach ($statement->targets ?? [] as $target) {
                        if ($target->type === SchemaObjectType::Index) {
                            $droppedIndexes[] = $target->qualifiedName();
                        }
                    }
                }

                continue;
            }

            if (! in_array($statement->statementKind, self::EXCLUSIVE_KINDS, true)) {
                continue;
            }

            // Validating a constraint or changing a maintenance storage parameter takes SHARE UPDATE
            // EXCLUSIVE, which a session holding a read or a write does not delay, so it is no target.
            if (ShareUpdateExclusiveAlter::only($statement->statementKind, $statement->canonicalSql ?? '')) {
                continue;
            }

            $stopsReaders = ! $this->addsOnlyAForeignKey($statement);

            foreach ($statement->targets ?? [] as $target) {
                // TABLES the statement ACTS ON, and both halves of that are load-bearing.
                //
                // A constraint is not a relation the activity views can report, so its name only
                // ever traveled here as dead weight. And a foreign key names a second table it
                // merely points at: PostgreSQL locks it SHARE ROW EXCLUSIVE, MySQL takes a shared
                // metadata lock on it, and neither is the lock this check reports on the table the
                // statement alters.
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
                // The QUALIFIED name, because that is what the activity views report a relation as.
                // A bare table name would match nothing on a schema-qualified server and everything
                // on none — both silently.
                $name = $target->qualifiedName();
                $targets[$name] = ($targets[$name] ?? false) || $stopsReaders;
            }
        }

        foreach (IndexTables::of($context->session, $droppedIndexes) as $table) {
            $targets[$table] = true;
        }

        return $targets;
    }

    /**
     * Whether the statement adds a foreign key and nothing else — the one `ALTER TABLE` form here that
     * takes SHARE ROW EXCLUSIVE rather than ACCESS EXCLUSIVE, and so lets readers through.
     *
     * A second action in the same statement takes its own lock, and the statement takes the stronger.
     */
    private function addsOnlyAForeignKey(CapturedStatement $statement): bool
    {
        return in_array($statement->statementKind, [StatementKind::AddConstraint, StatementKind::AddForeignKey], true)
            && $statement->actions === []
            && preg_match('/\bFOREIGN\s+KEY\b/i', $statement->canonicalSql ?? '') === 1;
    }

    /**
     * The first target this session holds a lock on that the migration's lock there has to wait for.
     *
     * ACCESS EXCLUSIVE waits for every held lock. SHARE ROW EXCLUSIVE waits for every one except a
     * reader's. A reading that tells no modes apart names one relation and nothing about the mode, so
     * that lock is taken to be in the way of everything, as it was before the modes were read.
     *
     * @param  array<string, bool>  $targets  relation => whether the lock taken there stops reads too
     */
    private function blockedTarget(LongRunningSession $session, array $targets): ?string
    {
        $held = $session->heldModes !== []
            ? $session->heldModes
            : ($session->relation === null ? [] : [$session->relation => null]);

        foreach ($held as $relation => $mode) {
            $relation = (string) $relation;

            if (! array_key_exists($relation, $targets)) {
                continue;
            }

            if ($targets[$relation] || $mode !== LockMode::Shared) {
                return $relation;
            }
        }

        return null;
    }

    /** Whether anything in the pending set builds an index concurrently. */
    private function hasConcurrentBuild(PreflightContext $context): bool
    {
        foreach ($context->pending->statements as $statement) {
            if ($statement->statementKind !== StatementKind::CreateIndex) {
                continue;
            }

            // Read off the SQL rather than off a flag, because `CONCURRENTLY` is not a separate
            // statement kind — it is a modifier on the same one, and the classification does not
            // split them.
            if (stripos($statement->canonicalSql ?? $statement->rawSql, 'concurrently') !== false) {
                return true;
            }
        }

        return false;
    }

    private function blocker(PreflightContext $context, LongRunningSession $session, string $relation, bool $stopsReaders): Finding
    {
        $collision = match ($stopsReaders) {
            true => 'this deploy is about to take an ACCESS EXCLUSIVE lock on that table. The statement will '
                .'not fail — it will QUEUE, and because PostgreSQL grants lock requests in order, every '
                .'read arriving behind it queues too. The table stops answering while nothing reports '
                .'an error.',
            false => 'this deploy is about to add a foreign key, which takes a SHARE ROW EXCLUSIVE lock on that '
                .'table. The statement will not fail — it will QUEUE, and every write arriving behind it '
                .'queues too, while reads carry on. Saves stop while nothing reports an error.',
        };

        return $this->finding(
            $context,
            self::ID,
            $relation,
            sprintf(
                'Session %s has been %s on `%s` for %.1F s, and %s Nothing here says that session is '
                .'wrong to be running; it says the migration is about to collide with it.',
                $session->session,
                $session->state,
                $relation,
                $session->runningForMs / 1000,
                $collision,
            ),
            Severity::High,
        );
    }

    private function concurrentBlocker(PreflightContext $context, int $sessions): Finding
    {
        return $this->finding(
            $context,
            self::CONCURRENTLY_ID,
            'concurrent index build',
            sprintf(
                'This deploy builds an index CONCURRENTLY, and %d session(s) have been running '
                .'longer than the threshold — on ANY table. A concurrent build waits for every '
                .'older transaction to finish, not only the ones touching its own table, so a long '
                .'query on an unrelated schema delays it just as effectively. The build does not '
                .'fail; it sits there, holding a SHARE UPDATE EXCLUSIVE lock for as long as the '
                .'oldest of them lives.',
                $sessions,
            ),
            Severity::Medium,
        );
    }

    private function finding(
        PreflightContext $context,
        string $ruleId,
        string $object,
        string $message,
        Severity $severity,
    ): Finding {
        return Finding::fail(
            ruleId: $ruleId,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: $message,
            location: Location::inCatalog($context->driver, $context->connection, $object, SchemaObjectType::Table),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for($ruleId),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: $severity,
        )->withDowntimeClass(
            // `blocking`, and here the axis says exactly what it means: the whole finding is about a
            // queue forming behind a lock request.
            DowntimeClass::Blocking,
        );
    }
}
