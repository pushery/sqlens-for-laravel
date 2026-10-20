<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Drivers\Pgsql\Deploy\InvalidIndexCheck;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\DeclaresLimitations;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An index PostgreSQL marks invalid: the remains of a `CREATE INDEX CONCURRENTLY` or a
 * `REINDEX CONCURRENTLY` that did not finish.
 *
 * The planner ignores such an index for every query, and nothing in the database mentions it again.
 * What else it costs depends on how far its build got, which the catalog reader states as `ready`:
 * an index that writes already reached is maintained on every INSERT and UPDATE, while the remains
 * of a build that failed earlier take no writes at all. Both hold their name, so the next run of the
 * migration that created them fails on a name that already exists.
 *
 * ## A build in flight is not wreckage
 *
 * An index is invalid on purpose while its build runs. The catalog reader therefore states for every
 * index whether a build is running on its table (`build_state`), and that answer is `undetermined`
 * rather than a finding. Where a build in the same database hides its relation from this session,
 * the reading cannot tell the two cases apart, and the answer is `undetermined` with that reason.
 *
 * {@see InvalidIndexCheck} reports the same state when a deploy is about to run, because the
 * migration that was interrupted is usually the one about to run again.
 *
 * ## No MySQL twin
 *
 * InnoDB has no such state: an index build is either committed or rolled back, and its catalog has
 * no flag equivalent to `indisvalid = false`.
 */
final class InvalidIndexRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, DeclaresLimitations, ProvidesSchemaObjectRemediation
{
    /** The key prefix of every note, precondition and verification string of the fix material. */
    private const string LANG = 'sqlens::messages.remediation.concurrently.';

    /**
     * The parts of an index definition as `pg_get_indexdef()` prints it: whether it is unique, its
     * name, whether it was built `ON ONLY` a partitioned table, and the schema of its table, each
     * identifier quoted where it needs to be.
     */
    private const string DEFINITION = '/^CREATE (?<unique>UNIQUE )?INDEX (?<name>"(?:[^"]|"")+"|[^\s"]+) ON (?<only>ONLY )?(?<schema>"(?:[^"]|"")+"|[^\s".]+)\./';

    /** A build is running on the index's table, so its invalid state may be the build's own. */
    private const string BUILD_RUNNING = 'running';

    /** No build is running on the index's table. */
    private const string NO_BUILD = 'none';

    /**
     * Indexes only: the state is a flag on the index's own catalog row.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Index];
    }

    public function id(): string
    {
        return 'PG.L7.INDEX_INVALID';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    /**
     * Performance, beside the other index rules of this level: the index serves no query and may
     * still be written. The failure a deploy meets on its name is the deploy suite's question, and
     * {@see InvalidIndexCheck} answers it there.
     */
    public function category(): Category
    {
        return Category::Performance;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        // Audit only: the state lives in pg_index, and a migration says nothing about whether an
        // earlier run of it was interrupted.
        return [Suite::Audit];
    }

    /** @return list<string> */
    public function limitations(): array
    {
        return [
            'a build is matched by its table, not by its index, so the remains of a failed build on a '
            .'table where another build is running come back undetermined rather than flagged',
            'an index created with CREATE INDEX ON ONLY on a partitioned table stays invalid until every '
            .'partition has an index attached to it, and it is reported while that sequence is under way',
        ];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Index || $object->getBool('valid') !== false) {
            return [];
        }

        $name = $object->qualifiedName;

        return match ($object->getString('build_state')) {
            self::NO_BUILD => [RuleVerdict::flag($this->leftoverMessage($name, $object->getBool('ready') !== false))],
            self::BUILD_RUNNING => [RuleVerdict::undetermined(sprintf(
                'The index %s is invalid, and an index build is running on its table right now. A '
                .'CREATE INDEX CONCURRENTLY or REINDEX CONCURRENTLY leaves its index invalid until it '
                .'finishes, so this may be that build at work rather than the remains of one that '
                .'failed. Run the audit again once the build has finished.',
                $name,
            ), UndeterminedReason::IndexBuildInProgress)],
            // `unverifiable`, and an absent value from a reading that did not ask: both mean that
            // whether a build is running here could not be established.
            default => [RuleVerdict::undetermined(sprintf(
                'The index %s is invalid, and whether a build is still running on it could not be '
                .'established: an index build in this database hides its table from this session, '
                .'which happens to a role without pg_read_all_stats. The remains of a failed build '
                .'should be dropped and an index that is still being built left alone, and this '
                .'reading cannot tell the two apart.',
                $name,
            ), UndeterminedReason::InvalidIndexFoundButBuildsUnverifiable)],
        };
    }

    /** What the remains of a failed build cost, and what to do about them. */
    private function leftoverMessage(string $name, bool $ready): string
    {
        $cost = $ready
            ? 'PostgreSQL ignores it for every query and still maintains it on every INSERT and UPDATE'
            : 'Its build failed before writes reached it, so it is neither used nor maintained';

        return sprintf(
            'The index %s is invalid and no build is running on its table: it is what remains of a '
            .'CREATE INDEX CONCURRENTLY or REINDEX CONCURRENTLY that did not finish. %s. It also '
            .'holds its name, so the next run of the migration that created it fails on a name that '
            .'already exists. Drop it with DROP INDEX CONCURRENTLY and create it again, outside a '
            .'transaction block; SQLens never runs either.',
            $name,
            $cost,
        );
    }

    /**
     * The fix material for the remains of a failed build: drop them concurrently, and build the index
     * again from its own definition.
     *
     * The strategy is `concurrently`. Both statements run concurrently and outside a transaction,
     * which is what keeps the repair from blocking writers, and that is what the strategy names. A
     * value of its own would cost a version of the published schema for a sequence the existing one
     * already describes.
     *
     * Three shapes. An ordinary index is dropped and rebuilt. A unique one gets a manual step between
     * the two, because a duplicate key is the usual reason a unique build fails, and the same
     * duplicates fail the rebuild. What a `REINDEX CONCURRENTLY` left behind, named `_ccnew` or
     * `_ccold`, is only dropped: the index it was rebuilding is still in place, and rebuilding the
     * leftover would create a second copy of it.
     *
     * The statements are built from the definition `pg_get_indexdef()` prints, which names the table
     * with its schema and quotes every identifier that needs it, measured on PostgreSQL 18 under a
     * search path that left the schema out. A definition in another shape gets no template, and so
     * does an index built `ON ONLY` a partitioned table: it becomes valid once every partition's
     * index is attached to it, and a rebuild is not the repair.
     */
    public function remediationForObject(SchemaObject $object): ?RemediationPayload
    {
        $flagged = array_filter(
            $this->judgeSchemaObject($object),
            static fn (RuleVerdict $verdict): bool => ! $verdict->isPass
                && ! $verdict->isUndetermined()
                && ! $verdict->notApplicableReason instanceof NotApplicableReason,
        );
        $definition = (string) $object->getString('definition');

        if ($flagged === [] || preg_match(self::DEFINITION, $definition, $parts) !== 1 || $parts['only'] !== '') {
            return null;
        }

        $plan = [[RemediationStepKind::SeparateMigration, 'drop_invalid', 'DROP INDEX CONCURRENTLY '.$parts['schema'].'.'.$parts['name']]];

        if (preg_match('/_cc(?:new|old)\d*"?$/', $parts['name']) === 1) {
            $plan[] = [RemediationStepKind::ManualGate, 'reindex_again', null];
        } else {
            if ($parts['unique'] !== '') {
                $plan[] = [RemediationStepKind::ManualGate, 'resolve_duplicates', null];
            }

            $plan[] = [RemediationStepKind::SeparateMigration, 'rebuild', (string) preg_replace('/^CREATE (UNIQUE )?INDEX /', 'CREATE $1INDEX CONCURRENTLY ', $definition, 1)];
        }

        $steps = [];

        foreach ($plan as $position => [$kind, $key, $sql]) {
            $steps[] = new RemediationStep(
                order: $position + 1,
                kind: $kind,
                noteKey: self::LANG.$key,
                sqlTemplate: $sql,
                withinTransaction: $kind !== RemediationStepKind::SeparateMigration,
            );
        }

        return new RemediationPayload(
            steps: $steps,
            strategy: RemediationStrategy::Concurrently,
            ruleId: $this->id(),
            preconditions: [self::LANG.'precondition.migrator_leaves_transaction'],
            verification: self::LANG.'state_verification',
            subject: RemediationSubject::SchemaObject,
        );
    }
}
