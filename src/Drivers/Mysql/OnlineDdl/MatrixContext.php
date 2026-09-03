<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * What a capture knows about the table and session a DDL operation runs against — the facts
 * that decide a matrix entry's edge predicates. It is deliberately three-valued per predicate:
 * a predicate is decided true, decided false, or NOT KNOWN.
 *
 * The single-file fast path knows nothing about a live table, so its context is {@see blind()}
 * — every predicate undecided, which is exactly why a plain ADD COLUMN resolves to undetermined
 * rather than a silent "instant". A richer capture (a live audit) supplies the facts it can read
 * with {@see with()}, and only then can a conditional entry resolve.
 */
final readonly class MatrixContext
{
    /** @param  array<string, bool>  $decided  predicate value → the fact this capture decided */
    private function __construct(private array $decided) {}

    /** A capture that decides nothing — the static fast path, where no table is inspected. */
    public static function blind(): self
    {
        return new self([]);
    }

    /** The same context with one more predicate decided; immutable, so callers chain safely. */
    public function with(OnlineDdlPredicate $predicate, bool $value): self
    {
        return new self([...$this->decided, $predicate->value => $value]);
    }

    /** The value this capture decided for the predicate, or null when it cannot decide it. */
    public function decide(OnlineDdlPredicate $predicate): ?bool
    {
        return $this->decided[$predicate->value] ?? null;
    }
}
