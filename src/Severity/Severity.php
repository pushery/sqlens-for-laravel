<?php

declare(strict_types=1);

namespace Pushery\SQLens\Severity;

/**
 * The risk axis, ordered and separate from the strictness level. Security and
 * privacy findings are gated by this axis, not by the level gate, so a level-2
 * run can still break on a Critical — and the reporter can show why.
 *
 * The backed string values are public API from 1.0 on. The order is stable
 * because governance allows severities to be *raised* in a minor (the security
 * exception); the threshold is configurable, never baked in.
 */
enum Severity: string
{
    case Info = 'info';
    case Low = 'low';
    case Medium = 'medium';
    case High = 'high';
    case Critical = 'critical';

    /** Total order rank. Higher is more severe. */
    public function rank(): int
    {
        return match ($this) {
            self::Info => 0,
            self::Low => 1,
            self::Medium => 2,
            self::High => 3,
            self::Critical => 4,
        };
    }

    /** Whether this severity is at least as severe as the given one. */
    public function isAtLeast(self $threshold): bool
    {
        return $this->rank() >= $threshold->rank();
    }
}
