<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Findings\Finding;

/**
 * What the escalation produced: the lint findings it weighed, and what it could not weigh.
 *
 * ## Why two lists and not one
 *
 * The two halves belong to different guarantees, and merging them would quietly break the stronger
 * one. A predeploy run promises that the ids in its LINT half are a subset of what `sqlens:lint`
 * reports — everything the gate says, CI could have said, only quieter. An id that only exists when
 * a database is reachable would be undeterminable in CI and unreproducible anywhere else.
 *
 * So a raise goes back into `$weighed`, where it changes a severity and nothing else, and the report
 * of an object that could not be measured goes into `$unweighed` as a `DEPLOY.PREFLIGHT.*` finding —
 * the same namespace every other check about the instance already uses.
 *
 * ## Why the absence is reported at all
 *
 * Nothing else would say it. The finding stands at the severity lint gave it, which is a correct
 * verdict, and a reader has no way to tell "this table is small" from "nobody could measure this
 * table". Those are different facts, and one of them is a reason to run ANALYZE before deploying.
 */
final readonly class EscalationOutcome
{
    /**
     * @param  list<Finding>  $weighed  the lint findings, with any earned raise applied
     * @param  list<Finding>  $unweighed  at most one `undetermined` naming every object left unmeasured
     */
    public function __construct(
        public array $weighed,
        public array $unweighed = [],
    ) {}
}
