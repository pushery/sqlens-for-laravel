<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Drivers\Mysql\Canonical\MysqlCanonicalization;

/**
 * The `ALGORITHM=` and `LOCK=` clauses an `ALTER TABLE` pins, read from its canonical text.
 *
 * A pinned clause is a condition the server meets or refuses the statement over; it never runs the
 * statement some other way. Measured on MySQL 8.4.10, each pin against two operations only a copy
 * can perform (`INT` to `BIGINT`, and a `latin1` column or table converted to `utf8mb4`) and one it
 * can perform in place (a `utf8mb3` column converted to `utf8mb4`):
 *
 * | Pin | copy-only operation | in-place operation |
 * |---|---|---|
 * | `LOCK=NONE` | refused | ran, reads and writes going on |
 * | `ALGORITHM=INPLACE` | refused | ran |
 * | `ALGORITHM=COPY, LOCK=NONE` | refused | |
 * | `ALGORITHM=INPLACE, LOCK=SHARED` | refused | |
 * | `LOCK=SHARED` | ran, as a copy under a shared lock | |
 *
 * So `LOCK=NONE` leaves two outcomes, a statement that runs while writes go on and one that does not
 * run, and `ALGORITHM=INSTANT` or `INPLACE` leaves no copy among them. A copy that queues writes is
 * then not one of the outcomes, unless `LOCK=SHARED` or `LOCK=EXCLUSIVE` asks for the queue.
 *
 * String literals are masked first, so a default that spells a clause cannot silence a rule.
 */
final readonly class PinnedDdlClauses
{
    private function __construct(
        public ?string $algorithm,
        public ?string $lock,
    ) {}

    public static function of(string $canonical): self
    {
        $masked = StringLiteralMask::forDriver(new MysqlCanonicalization)->apply($canonical);

        return new self(self::valueOf('ALGORITHM', $masked), self::valueOf('LOCK', $masked));
    }

    /**
     * Whether the pins leave the server no way to run the statement as a copy that queues writes:
     * `LOCK=NONE`, or `ALGORITHM=INSTANT` or `INPLACE` without a lock level that queues them.
     */
    public function ruleOutAQueuingCopy(): bool
    {
        if ($this->lock === 'NONE') {
            return true;
        }

        return in_array($this->algorithm, ['INSTANT', 'INPLACE'], true)
            && ! in_array($this->lock, ['SHARED', 'EXCLUSIVE'], true);
    }

    /** The clause's value in upper case, or null when the statement does not pin it. */
    private static function valueOf(string $clause, string $masked): ?string
    {
        return preg_match('/\b'.$clause.'\s*=\s*([A-Z]+)/i', $masked, $match) === 1 ? strtoupper($match[1]) : null;
    }
}
