<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Catalog\Statistics\StatisticsRequest;
use Pushery\SQLens\Catalog\Statistics\TableStatistics;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\StatisticsReader;
use Pushery\SQLens\Drivers\DriverRegistry;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\StatisticsContext;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * The lint findings of a preflight, weighed against how big the objects they name actually are.
 *
 * This is the step that makes a predeploy run worth more than the CI lint it repeats. CI sees a
 * COPY-forcing `ALTER` and reports it; only a run with the database in front of it can say whether
 * that table holds four hundred rows or four hundred million.
 *
 * ## Why this is a class and not a method on the service
 *
 * It was a private method on {@see PreflightService} first, and that is exactly how the escalator
 * came to sit complete-but-unwired for six rounds: everything about the decision was reachable only
 * through a run against a live database, so nothing could be exercised without one, so nothing was.
 * The service composes a preflight; deciding which findings get weighed and against what is a
 * judgment of its own, and a judgment that cannot be tested directly is one that rots directly.
 *
 * ## Three ways it declines, and all three leave the finding alone
 *
 * A rule that declares no operation class is not asked about — most rules judge a STATE, and no size
 * changes what that means. A statistics reader that is absent, or that cannot answer for the object,
 * leaves the finding as lint produced it. And {@see SeverityEscalator} itself only ever raises.
 *
 * So the failure direction here is "no escalation", never "wrong severity" — which is the one to
 * have, because an un-escalated verdict was already the honest one.
 */
final readonly class FindingEscalation
{
    /**
     * What a run reports when it could not measure an object a finding names.
     *
     * A `DEPLOY.PREFLIGHT.*` id rather than anything in the lint namespace, deliberately: this is a
     * statement about the INSTANCE — the same kind every other preflight check makes — and putting
     * it in the lint half would create an id that only exists when a database is reachable.
     */
    public const string UNREAD_ID = 'DEPLOY.PREFLIGHT.STATISTICS_UNREAD';

    public function __construct(
        private DriverRegistry $drivers,
        private SeverityEscalator $escalator,
    ) {}

    /** @param  list<Finding>  $findings */
    public function applyTo(array $findings, PreflightContext $context): EscalationOutcome
    {
        $driver = $this->drivers->resolve($context->driver);

        if (! $driver instanceof Driver || ! $context->statistics instanceof StatisticsReader) {
            // No reader is not the same absence as an unread object, and it is not reported here:
            // a run with no statistics reader at all has already said so through the checks that
            // needed one. One absence reported twice reads as two problems.
            return new EscalationOutcome($findings);
        }

        $declared = OperationClassRegistrar::byRuleId(array_values([...$driver->rules()]));
        $objects = $this->objectsNamedBy($findings, $declared);

        if ($objects === []) {
            return new EscalationOutcome($findings);
        }

        try {
            $snapshot = $context->statistics->read(new StatisticsRequest(
                objects: $objects,
                // The budget the run has LEFT, not a fresh one. A preflight holds one deadline across
                // every check, and a read that started its own would let the escalation overrun a
                // bound the rest of the run is honoring, in front of a deploy.
                budgetMilliseconds: $context->remainingBudgetMs(),
            ));
        } catch (Throwable) {
            // Unreadable statistics are not a reason to fail a deploy gate: the findings stand at the
            // severity lint gave them, which is what a run without a database would have reported
            // anyway. The catalog checks report their own inability separately and by name, so the
            // absence is still visible — once, rather than twice as two problems.
            return new EscalationOutcome($findings);
        }

        $weighed = array_map(
            function (Finding $finding) use ($declared, $snapshot): Finding {
                $operation = OperationClassRegistrar::for($finding, $declared);
                $object = $finding->location->objectName;

                if ($operation === null || $object === null) {
                    return $finding;
                }

                $table = $snapshot->forTable($object);

                return $this->escalator->escalate(
                    $finding,
                    $operation,
                    $table instanceof TableStatistics
                        ? StatisticsContext::of($table->rows, $table->totalBytes)
                        : null,
                );
            },
            $findings,
        );

        // Read off the SNAPSHOT rather than accumulated while mapping. The accessor exists for this
        // exact purpose and its own docblock says why — a table missing from `$tables` is invisible
        // to every loop over them, so a consumer that only walks the answers can never notice the
        // absence. Collecting it in the map instead was also a captured-by-value bug the type
        // checker caught: the closure would have filled a local array and discarded it.
        $unread = $snapshot->unanswered();

        return new EscalationOutcome(
            $weighed,
            $unread === [] ? [] : [$this->unreadFinding($unread, $context)],
        );
    }

    /**
     * One finding naming every object that could not be measured — not one per object.
     *
     * A gate somebody reads before a deploy is a gate that has to stay readable. Twelve findings
     * saying the same sentence about twelve tables is the shape people switch off; one that names
     * twelve tables is the shape they act on.
     *
     * @param  list<string>  $objects
     */
    private function unreadFinding(array $objects, PreflightContext $context): Finding
    {
        sort($objects);

        return Finding::undetermined(
            self::UNREAD_ID,
            DeployNotice::MESSAGE_PREFIX,
            sprintf(
                'The statistics reading came back without %s, so the findings about %s could not be '
                .'weighed against %s size: %s. Every verdict still stands exactly as `sqlens:lint` '
                .'produced it — what is missing is only the raise a large object would have earned, '
                .'which means a real problem here can be reported quieter than it deserves. A table '
                .'nobody has run ANALYZE on is the commonest cause, and running it is the fix.',
                count($objects) === 1 ? 'one object' : count($objects).' objects',
                count($objects) === 1 ? 'it' : 'them',
                count($objects) === 1 ? 'its' : 'their',
                implode(', ', $objects),
            ),
            UndeterminedReason::ObjectStatisticsUnread,
            Location::inCatalog($context->driver, $context->connection, $objects[0], SchemaObjectType::Table),
            Category::Safety,
            Level::Capturable,
            StabilityTier::Stable,
            RuleDocumentationUrl::for(self::UNREAD_ID),
            new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
        );
    }

    /**
     * The objects worth asking about, as ONE list.
     *
     * One request rather than one per finding, because each is a catalog round trip against a
     * database somebody is about to deploy to, on a budget shared with every check after it. Three
     * migrations touching the same table ask once.
     *
     * @param  list<Finding>  $findings
     * @param  array<string, string>  $declared
     * @return list<string>
     */
    private function objectsNamedBy(array $findings, array $declared): array
    {
        $objects = [];

        foreach ($findings as $finding) {
            $object = $finding->location->objectName;

            if ($object !== null && OperationClassRegistrar::for($finding, $declared) !== null) {
                $objects[$object] = true;
            }
        }

        return array_keys($objects);
    }
}
