<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Indexes\UnusedIndex;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An index nobody has read — as far as counters that can be reset are able to say.
 *
 * ## Why this one is EXPERIMENTAL when every other rule before 1.0 is stable
 *
 * Not maturity. Every other rule in this package answers from the schema, and the schema does not
 * move while you look at it. This one answers from counters, and its verdict therefore depends on
 * WHEN it is asked — which is a direct tension with the package's third governing principle, that
 * the same state produces the same result.
 *
 * The tier is what keeps that tension out of everybody else's run. `experimental` is not admitted by
 * default, so a project that has not asked for this rule gets an audit whose determinism is intact.
 * A project that HAS asked for it has accepted a time-bounded question, knowingly.
 *
 * That is a deliberate, named exception to the pre-1.0 rule that every shipped rule is `stable`, and
 * the guard holding that rule carries this id with the reason beside it rather than being loosened.
 *
 * ## The window is the whole difficulty
 *
 * Measured on PostgreSQL 18.4: `pg_stat_database.stats_reset` is NULL on a cluster nobody has reset
 * — the ordinary state. A zero count over a window that started at an unrecorded moment is not
 * evidence of anything, so it is `undetermined` with the reason named, never a pass and never a
 * finding. Same when the window is real but shorter than the project's minimum.
 *
 * The finding quotes the count and the window's START, not the elapsed time. That number moves
 * between two audits of an unchanged database, and this package's reports are meant to be diffable.
 *
 * ## What it will never report
 *
 * A primary key or a unique index. "Nobody queried it" is not an argument about a constraint — that
 * index exists to refuse a write, and it has been doing so silently the whole time.
 */
final class UnusedIndexRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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

    private readonly int $minObservationDays;

    public function __construct(string $projectRoot, ?int $minObservationDays = null)
    {
        parent::__construct($projectRoot);

        $this->minObservationDays = $minObservationDays ?? 30;
    }

    public function id(): string
    {
        return 'PG.L7.INDEX_UNUSED';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    public function category(): Category
    {
        return Category::Performance;
    }

    #[Override]
    public function stability(): StabilityTier
    {
        return StabilityTier::Experimental;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        if (! UnusedIndex::wasRead($object)) {
            return [RuleVerdict::undetermined(sprintf(
                'The index usage statistics for %s could not be read, so whether any of its indexes has ever '
                .'been scanned is unknown. That is not a pass: a role that cannot see pg_stat_user_indexes and '
                .'a table whose indexes are genuinely unused produce the same empty answer.',
                $object->qualifiedName,
            ), UndeterminedReason::IndexUsageWindowUnknown)];
        }

        $window = UnusedIndex::windowStart($object);

        // Zero days is a project SAYING "report on whatever window the server has" — so an unknown
        // window is accepted rather than refused. Without this the message below would promise
        // something the code does not do, which is worse than either answer on its own.
        if ($window === null && $this->minObservationDays > 0) {
            return [RuleVerdict::undetermined(sprintf(
                'On %s the index scan counters were read, but the server has never reset them — '
                .'pg_stat_database.stats_reset is NULL — so the window they cover starts at a moment nobody '
                .'recorded. A zero count over an unknown window is not evidence, and reporting it as one would '
                .'be advising a DROP on the strength of a number whose age nobody knows.',
                $object->qualifiedName,
            ), UndeterminedReason::IndexUsageWindowUnknown)];
        }

        $days = UnusedIndex::windowDays($object);

        if ($this->minObservationDays > 0 && ($days === null || $days < $this->minObservationDays)) {
            return [RuleVerdict::undetermined(sprintf(
                'On %s the counters have been running since %s, which is %s the %d day(s) this project requires '
                .'before a zero scan count counts as evidence. A short window is not a clean bill of health: the '
                .'monthly report that is the only reader of an index has not run yet.',
                $object->qualifiedName,
                // Not nullable here: the arm above already returned for an unknown window whenever
                // a window was required at all, so reaching this branch means one was read.
                $window,
                $days === null ? 'not a length anyone could establish against' : 'shorter than',
                $this->minObservationDays,
            ), UndeterminedReason::IndexUsageWindowUnknown)];
        }

        $unused = UnusedIndex::on($object);

        if ($unused === []) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            'On %s, %s never been scanned since the statistics were reset at %s: %s. An index nobody reads is '
            .'still written on every insert and on every update touching its columns, occupies its own pages in '
            .'cache, and is one more relation for vacuum to walk. Before dropping it, check the two things this '
            .'counter cannot see: statistics are PER INSTANCE, so an index read only on a replica looks unused '
            .'here, and a query that runs monthly has not run yet if the window is shorter than a month. This '
            .'run required at least %d day(s) of window. Drop with DROP INDEX CONCURRENTLY when you are '
            .'satisfied; SQLens never runs it.',
            $object->qualifiedName,
            count($unused) === 1 ? 'an index has' : count($unused).' indexes have',
            $window ?? 'a point this engine does not record',
            implode(', ', array_keys($unused)),
            $this->minObservationDays,
        ))];
    }
}
