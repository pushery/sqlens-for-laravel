<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

/**
 * Where in a migration's control flow a call sits.
 *
 * The pre-scan needs this to tell a real hit from noise. `->count()` appears in
 * migrations constantly and is harmless when its result is only logged; it is a
 * hit when the migration BRANCHES on it, because under pretend the count is zero
 * and the branch never taken. Without the distinction the detector would flag
 * every migration that counts anything, and a rule that flags everything gets
 * switched off — at which point it protects nothing.
 *
 * `insideCondition` follows the value, not only the position: a call decides a
 * branch where it stands in the deciding expression, where it is assigned to a
 * variable such an expression reads, and where a method of the migration returns
 * it and that method's call decides a branch. `if (! $exists)` after
 * `$exists = Schema::hasTable('t')` branches on the table as much as
 * `if (! Schema::hasTable('t'))` does.
 *
 * `insideLoopBody` carries the same idea for the classic backfill: DDL emitted
 * from inside a loop over query results is DDL the capture never sees, because
 * the loop runs zero times.
 */
final readonly class CallContext
{
    public function __construct(
        public bool $insideCondition,
        public bool $insideLoopBody,
        public bool $loopIterablesAreLiteral,
    ) {}

    /** A call in plain straight-line code. */
    public static function plain(): self
    {
        return new self(false, false, false);
    }

    /**
     * Whether this call sits in a loop whose iteration count the scanner cannot
     * see — the shape that makes a backfill invisible under pretend. A loop over
     * a written-out array is excluded: it runs the same number of times whether
     * or not a database answers.
     */
    public function insideUnboundedLoop(): bool
    {
        return $this->insideLoopBody && ! $this->loopIterablesAreLiteral;
    }
}
