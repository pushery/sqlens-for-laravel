<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Activity;

use Pushery\SQLens\Exceptions\InvalidActivityRequest;

/**
 * What a live-activity reading was ASKED for.
 *
 * Unlike a statistics request, this one does NOT name objects it must be given. The difference is
 * the question: statistics weight findings that already exist, so the objects worth reading about
 * are the ones some finding already references — while a lock queue is dangerous precisely when it
 * involves a table nobody predicted. A preflight scoped to the migration's own tables would miss
 * the long-running transaction three tables over that is holding the horizon and will stall the
 * index build anyway.
 *
 * So the objects here are a FOCUS, not a filter: a reader reports what it finds and marks which
 * rows touch them.
 */
final readonly class ActivityRequest
{
    /** @var list<string> */
    public array $objects;

    /** @param  list<string>  $objects  the relations this deploy is about, for emphasis rather than exclusion */
    public function __construct(
        array $objects = [],
        /**
         * How long a session must have been running to be worth reporting, in milliseconds.
         *
         * A threshold rather than "report everything", because every busy server has hundreds of
         * sessions and a preflight that listed them all would be read once. Its default is
         * deliberately low for a deploy: a transaction open for five seconds is unremarkable during
         * the day and is exactly the thing to know about in the minute before a migration.
         */
        public int $longRunningThresholdMs = 5_000,
        /**
         * Whether replication state is read at all.
         *
         * Off by default, and that is a cost decision rather than a scope one: on a primary the
         * view is cheap, but a project with no replicas would pay a round trip to be told so on
         * every single preflight.
         */
        public bool $includeReplication = false,
        /** This reading's share of the run's time budget, in milliseconds. */
        public int $budgetMilliseconds = 2_000,
    ) {
        if ($longRunningThresholdMs <= 0) {
            throw InvalidActivityRequest::hasNoThreshold($longRunningThresholdMs);
        }

        if ($budgetMilliseconds <= 0) {
            throw InvalidActivityRequest::hasNoTimeBudget($budgetMilliseconds);
        }

        foreach ($objects as $object) {
            if (trim($object) === '') {
                throw InvalidActivityRequest::namesAnEmptyObject();
            }
        }

        $objects = array_values(array_unique($objects));
        sort($objects);

        $this->objects = $objects;
    }

    /** Whether a relation is one this deploy is about. */
    public function focusesOn(string $relation): bool
    {
        return in_array($relation, $this->objects, true);
    }

    /** @return array{objects: list<string>, long_running_threshold_ms: int, include_replication: bool, budget_ms: int} */
    public function toArray(): array
    {
        return [
            'objects' => $this->objects,
            'long_running_threshold_ms' => $this->longRunningThresholdMs,
            'include_replication' => $this->includeReplication,
            'budget_ms' => $this->budgetMilliseconds,
        ];
    }
}
