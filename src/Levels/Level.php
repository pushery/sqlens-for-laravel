<?php

declare(strict_types=1);

namespace Pushery\SQLens\Levels;

/**
 * The strictness axis, cumulative in the Larastan sense: a run at level N
 * includes every rule up to and including N. This is the gate the rule catalog
 * is sliced by.
 *
 * A rule's level membership is DRIVER-SPECIFIC — the same rule class can sit at
 * a different level on PostgreSQL than on MySQL. The level here is the axis, not
 * the assignment; assignment lives with each rule.
 *
 * Levels model strictness appetite, NOT risk. Security and privacy rules are
 * gated by the separate severity axis and ignore the level gate entirely
 * (see Category::usesSeverityGate()).
 */
enum Level: int
{
    case Capturable = 0;
    case Destructive = 1;
    case BlockingDdl = 2;
    case LockHygiene = 3;
    case BackwardCompatibility = 4;
    case SchemaBasics = 5;
    case TypeIdiom = 6;
    case PerformanceHeuristics = 7;
    case Conventions = 8;
    case Pedantic = 9;

    /**
     * Cumulative membership: an active level includes a rule iff the rule sits at
     * this level or below. This is the whole meaning of "level 4 runs everything
     * up to 4".
     */
    public function includes(self $rule): bool
    {
        return $rule->value <= $this->value;
    }

    /** Whether this level is at least as strict as the given one. */
    public function atLeast(self $other): bool
    {
        return $this->value >= $other->value;
    }

    /**
     * A one-line English description, used as the single source for the generated
     * rule docs and sqlens:agent-rules — never re-authored in the doc generator.
     */
    public function description(): string
    {
        return match ($this) {
            self::Capturable => 'The migration SQL can be captured and runs clean in pretend mode.',
            self::Destructive => 'Destructive operations without an explicit opt-in.',
            self::BlockingDdl => 'Blocking DDL: the core lock-taking schema changes.',
            self::LockHygiene => 'Lock hygiene: session timeouts and risky operations bundled in one transaction.',
            self::BackwardCompatibility => 'Backward compatibility across a deploy window.',
            self::SchemaBasics => 'Schema basics: missing primary keys, unindexed foreign keys, money as float.',
            self::TypeIdiom => 'Type idiom: timestamptz, jsonb, identity columns, utf8mb4.',
            self::PerformanceHeuristics => 'Performance heuristics: redundant or unused indexes, predicate-aware.',
            self::Conventions => 'Conventions: naming schemes and structural house style.',
            self::Pedantic => 'Pedantic: the strictest, most opinionated checks.',
        };
    }
}
