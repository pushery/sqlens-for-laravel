<?php

declare(strict_types=1);

namespace Pushery\SQLens\Categories;

/**
 * The category axis, orthogonal to suites and levels. It drives the global
 * --category filter and decides which rules are gated by severity instead of by
 * the level gate.
 *
 * A category is NOT a suite: a `safety` rule runs in both lint and deploy. The
 * core never maps a category to a suite.
 *
 * The backed string values are public API from 1.0 on — they appear in the JSON
 * and SARIF output and in config filters, so renaming one is a breaking change.
 */
enum Category: string
{
    case Safety = 'safety';
    case Performance = 'performance';
    case Idiom = 'idiom';
    case Convention = 'convention';
    case Security = 'security';
    case Privacy = 'privacy';

    /**
     * The machine form of "levels model strictness appetite, security models
     * risk": security and privacy rules ignore the level gate and are gated by
     * their own severity instead.
     */
    public function usesSeverityGate(): bool
    {
        return match ($this) {
            self::Security, self::Privacy => true,
            default => false,
        };
    }

    /**
     * A one-line English description, used as the single source for the generated
     * rule docs and sqlens:agent-rules.
     */
    public function description(): string
    {
        return match ($this) {
            self::Safety => 'Migration and schema changes that risk downtime or data loss.',
            self::Performance => 'Query and schema shapes that cost performance.',
            self::Idiom => 'Non-idiomatic types and constructs for the target engine.',
            self::Convention => 'House-style and naming conventions.',
            self::Security => 'Database-adjacent security: roles, grants, exposure, injection.',
            self::Privacy => 'Personal-data handling: unencrypted sensitive columns, logging exposure.',
        };
    }
}
