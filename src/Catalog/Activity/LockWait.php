<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Activity;

/**
 * One session waiting on a lock another session holds.
 *
 * The row a live preflight exists to find, and the one this package must never lose.
 *
 * ## The mode may be unknown; the row may not be missing
 *
 * `$mode` is nullable and `$rawMode` never is, and that pairing is the whole design. A server can
 * report a lock in a mode this build has no neutral name for — a newer engine, a provider
 * extension, a type nobody here has met — and the tempting handling is to skip the row while
 * mapping. That would delete a BLOCKING LOCK from the picture and report calm at the one moment
 * calm matters most.
 *
 * So an unmappable mode costs the name and nothing else. The row keeps its waiter, its holder, its
 * relation and the server's own spelling of the mode, and {@see ActivitySnapshot} turns the missing
 * name into a named skip on its own initiative. There is no code path that drops one.
 *
 * ## What is not here, and will not be
 *
 * The query text. A waiting session's statement is the most tempting field on the whole object and
 * the one that carries literals — a `WHERE email = …` with its value, a token, an address — into a
 * report, a CI log, and wherever that log gets pasted. The relation, the duration and the mode are
 * what a decision is made on; the statement is what makes the decision quotable, and this package
 * does not trade the first for the second.
 */
final readonly class LockWait
{
    public function __construct(
        /** The session that is waiting, as the server identifies it. */
        public string $waiter,
        /** The session holding the lock it waits for, or null when the server names no single one. */
        public ?string $holder,
        /** The relation the two are contending over, qualified as the reading names it. */
        public string $relation,
        /**
         * The neutral mode, or null when this build has no name for what the server reported.
         *
         * Null is never "no lock" and never "harmless". It is "we saw a lock and could not classify
         * it", which is strictly more alarming than any mode in the enum — an unfamiliar mode is by
         * definition one nobody has reasoned about.
         */
        public ?LockMode $mode,
        /**
         * The server's own spelling, always. It is what makes an unmapped row actionable and what a
         * later mapping is written from.
         */
        public string $rawMode,
        /** How long the waiter has been waiting, in milliseconds, or null when the server withholds it. */
        public ?int $waitingForMs = null,
    ) {}

    /** Whether this row carries a mode this build could name. */
    public function isMapped(): bool
    {
        return $this->mode instanceof LockMode;
    }

    /** The stable sort key — relation first, so contention on one table reads together. */
    public function sortKey(): string
    {
        return $this->relation.':'.$this->waiter.':'.$this->rawMode;
    }

    /** @return array{waiter: string, holder: string|null, relation: string, mode: string|null, raw_mode: string, waiting_for_ms: int|null} */
    public function toArray(): array
    {
        return [
            'waiter' => $this->waiter,
            'holder' => $this->holder,
            'relation' => $this->relation,
            'mode' => $this->mode?->value,
            'raw_mode' => $this->rawMode,
            'waiting_for_ms' => $this->waitingForMs,
        ];
    }
}
