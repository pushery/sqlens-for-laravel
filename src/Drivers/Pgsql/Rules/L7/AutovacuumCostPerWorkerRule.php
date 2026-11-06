<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlSettingCrossFactCollector;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\DeclaresLimitations;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * More autovacuum workers than the cost limit they share pays for.
 *
 * ## One budget, split between the workers that run
 *
 * `autovacuum_vacuum_cost_limit` is not a limit per worker. PostgreSQL divides it among the workers
 * running at the same time, so that the sum of their limits never exceeds it. Raising
 * `autovacuum_max_workers` without raising the limit adds no throughput: each worker gets a smaller
 * share, sleeps sooner, and every single vacuum takes longer. A vacuum that keeps falling behind
 * ends in the anti-wraparound vacuum, which does not yield to the DDL of a deploy.
 *
 * ## What is compared
 *
 * The workers that can run: `autovacuum_max_workers`, capped by `autovacuum_worker_slots`, the pool
 * PostgreSQL 18 takes them from. The limit they share: `autovacuum_vacuum_cost_limit`, or
 * `vacuum_cost_limit` where it is `-1`, the default. Both are read as the value a new connection
 * gets, and the `-1` is resolved rather than read literally: a rule that fired on `-1` would blame a
 * server that raised `vacuum_cost_limit` properly and say nothing about ten workers on an explicit
 * 200.
 *
 * Each worker's share is held against the share the defaults give, 200 split three ways. Only a
 * server that runs more than the default three workers is this rule's subject: three workers on a
 * lower limit is a slower vacuum chosen on purpose, not one diluted by workers nobody paid for.
 *
 * ## No MySQL twin
 *
 * InnoDB purges with its own threads and has no cost-based delay that more threads would share.
 */
final class AutovacuumCostPerWorkerRule extends AbstractServerSettingRule implements DeclaresLimitations
{
    /** The worker count PostgreSQL ships, whose share of the default limit every server is held against. */
    private const int DEFAULT_WORKERS = 3;

    /** The default `vacuum_cost_limit`, which `autovacuum_vacuum_cost_limit = -1` inherits. */
    private const int DEFAULT_COST_LIMIT = 200;

    public function id(): string
    {
        return 'PG.L7.AUTOVACUUM_COST_PER_WORKER';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    /**
     * Performance: nothing is lost while the vacuum is slow, but every table it reaches late grows,
     * and every estimate taken from it is worth less.
     */
    public function category(): Category
    {
        return Category::Performance;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'autovacuum_max_workers';
    }

    /**
     * Judged from the relation between three settings, which no matrix entry can hold: the number
     * of workers is not wrong on its own, only against the limit they share.
     */
    #[Override]
    protected function bringsOwnExpectation(): bool
    {
        return true;
    }

    /**
     * The shared limit and the worker pool, declared, so a read that failed reports `undetermined`
     * with its reason instead of going quiet.
     *
     * @return list<string>
     */
    #[Override]
    protected function requiredCrossFacts(): array
    {
        return [
            PgsqlSettingCrossFactCollector::AUTOVACUUM_COST_LIMIT,
            PgsqlSettingCrossFactCollector::AUTOVACUUM_WORKER_POOL,
        ];
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        $configured = $this->whole($serverValue);
        $limit = $this->whole($this->crossFact($object, PgsqlSettingCrossFactCollector::AUTOVACUUM_COST_LIMIT) ?? '');
        $pool = $this->whole($this->crossFact($object, PgsqlSettingCrossFactCollector::AUTOVACUUM_WORKER_POOL) ?? '');

        if ($configured === null || $limit === null) {
            return null;
        }

        // The pool caps the setting: a value above autovacuum_worker_slots has no effect.
        $workers = $pool === null ? $configured : min($configured, $pool);

        if ($workers <= self::DEFAULT_WORKERS || $limit * self::DEFAULT_WORKERS >= self::DEFAULT_COST_LIMIT * $workers) {
            return null;
        }

        return sprintf(
            'autovacuum may run %d workers at once, and they share a cost limit of %d, so each gets %d '
            .'where the defaults give each of three workers %d. The limit is divided among the workers '
            .'that run rather than given to each, so the workers beyond three add no throughput: every '
            .'one of them sleeps sooner and each vacuum takes longer, and a vacuum that keeps falling '
            .'behind ends in the anti-wraparound vacuum, which does not yield to a deploy. Raise '
            .'autovacuum_vacuum_cost_limit to %d to give each worker the default share again, or run '
            .'fewer workers.',
            $workers,
            $limit,
            intdiv($limit, $workers),
            intdiv(self::DEFAULT_COST_LIMIT, self::DEFAULT_WORKERS),
            (int) ceil(self::DEFAULT_COST_LIMIT * $workers / self::DEFAULT_WORKERS),
        );
    }

    /**
     * @return list<string>
     */
    public function limitations(): array
    {
        return [
            'a table that sets its own autovacuum_vacuum_cost_limit or autovacuum_vacuum_cost_delay storage parameter is left out of the split by PostgreSQL, and this rule reads the server\'s settings rather than every table\'s options',
            'counts the workers the server may run, not the ones running now: a server whose tables rarely need a vacuum may never start more than one worker, and then nothing is split',
        ];
    }

    /** The setting as a whole number, or null for a value that is not one. */
    private function whole(string $value): ?int
    {
        $value = trim($value);

        return preg_match('/^-?\d+$/', $value) === 1 ? (int) $value : null;
    }
}
