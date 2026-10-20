<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A PostgreSQL server that hands new connections `track_counts = off`.
 *
 * The counters this setting feeds are what autovacuum decides by, so with them off no table is
 * vacuumed or analyzed on its own, even while `autovacuum` itself is on: {@see AutovacuumOffRule}
 * by another name, and one that reads as healthy in the setting everybody checks first.
 *
 * The same counters are the evidence {@see UnusedIndexRule} judges by. A scan made without them is
 * not counted, so on such a server an index looks unused whether it is or not, and that rule answers
 * undetermined there instead of advising a drop.
 *
 * Read as the value a new connection gets, never as the reading session's own: a superuser may
 * switch it off for one session, and that says nothing about the connections an application makes.
 *
 * ## No MySQL twin
 *
 * InnoDB's purge runs whatever is configured, so the autovacuum half has no counterpart there. The
 * index usage half does, in `performance_schema`, and the MySQL reader already treats a disabled
 * performance schema as a usage reading it could not make.
 */
final class TrackCountsOffRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'PG.L7.TRACK_COUNTS_OFF';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    /** Performance, for the reason {@see AutovacuumOffRule} gives: nothing is lost, much degrades. */
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
        return 'track_counts';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        if (strcasecmp($serverValue, $expectation->expectation ?? 'on') === 0) {
            return null;
        }

        return sprintf(
            'track_counts is off for new connections, so the server stops counting row changes and '.
            'index scans. Autovacuum decides by those counts: without them it vacuums and analyzes no '.
            'table on its own, even though autovacuum itself is on. The index scan counters stop as '.
            'well, which is why PG.L7.INDEX_UNUSED does not judge on this server. %s',
            $this->remediation($expectation),
        );
    }
}
