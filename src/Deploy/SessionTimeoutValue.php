<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * A session timeout as milliseconds, from whatever shape the server answered with.
 *
 * Engine-NEUTRAL on purpose, which is why it sits in the core rather than in either driver:
 * PostgreSQL answers with a unit suffix (`5s`, `5000ms`, `1min`) and MySQL with a bare number, and
 * reducing both to milliseconds is arithmetic rather than engine knowledge. Two copies of this
 * parser — one per driver — would be exactly the duplicate this seam was split out to avoid.
 *
 * **Zero survives as zero.** Zero means NO TIMEOUT on both engines, which is exactly the state the
 * session-defense check exists to catch; folding it into null would make "unbounded" and "unreadable"
 * the same answer, and only one of those is a defect in the run.
 */
final readonly class SessionTimeoutValue
{
    /** @return int|null milliseconds, or null when the server did not answer with a timeout at all */
    public static function milliseconds(object $row, string $key): ?int
    {
        $value = $row->{$key} ?? null;

        if (! is_scalar($value)) {
            return null;
        }

        $raw = trim((string) $value);

        if (preg_match('/^(\d+)\s*(ms|s|min)?$/', $raw, $match) !== 1) {
            return null;
        }

        return (int) $match[1] * match ($match[2] ?? '') {
            's' => 1_000,
            'min' => 60_000,
            default => 1,
        };
    }
}
