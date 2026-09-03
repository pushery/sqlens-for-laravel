<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Pushery\SQLens\Subjects\FragmentOrigin;
use Pushery\SQLens\Subjects\ParametrizationSignal;

/**
 * What the classifier saw at one raw-SQL call site: a three-valued signal, the syntactic shape it
 * came from, and — when the answer is "I cannot tell" — the reason.
 *
 * ## It reuses the package's vocabulary rather than minting a parallel one
 *
 * {@see ParametrizationSignal} and {@see FragmentOrigin} have existed since the `RawSql` subject was
 * defined, and they say exactly what a classifier of this kind has to say. The planning ticket
 * speaks of `safe` / `unsafe` / `undetermined`; those are the same three values under different
 * names, and a second enum spelling them differently is how one component comes to have two
 * vocabularies that are free to drift. The names here are the ones already shipped.
 *
 * The choice of `Parametrized` / `Interpolated` over `safe` / `unsafe` is also load-bearing rather
 * than cosmetic. This is a SYNTACTIC observation, not a security verdict: "the text is fully known
 * at analysis time" is something a parser can prove, "this query is safe" is not. A rule may build a
 * finding on top of the observation — that is the rules' job — but the observation itself never
 * claims more than it saw.
 */
final readonly class ParameterizationVerdict
{
    private function __construct(
        public ParametrizationSignal $signal,
        public FragmentOrigin $origin,
        public ?UndeterminedReason $reason,
    ) {}

    /** The SQL text is fully known at analysis time — no runtime value reaches the statement's shape. */
    public static function parametrized(FragmentOrigin $origin): self
    {
        return new self(ParametrizationSignal::Parametrized, $origin, null);
    }

    /** Something non-constant was visibly assembled into the SQL text. */
    public static function interpolated(FragmentOrigin $origin): self
    {
        return new self(ParametrizationSignal::Interpolated, $origin, null);
    }

    /**
     * The classifier could not see, and names why.
     *
     * The reason is REQUIRED here rather than nullable, which is the whole point of the factory: an
     * `undetermined` without a reason is indistinguishable from a check that never ran, and this
     * type makes that state unconstructible instead of merely discouraged.
     */
    public static function undetermined(FragmentOrigin $origin, UndeterminedReason $reason): self
    {
        return new self(ParametrizationSignal::Undetermined, $origin, $reason);
    }

    /**
     * A single token a report or a test can compare — the signal, plus the reason when there is one.
     *
     * Deterministic by construction: two enum values joined by a fixed separator, with no path, no
     * timestamp and no locale-dependent ordering anywhere in it.
     */
    public function describe(): string
    {
        return $this->reason instanceof UndeterminedReason
            ? $this->signal->value.':'.$this->reason->value
            : $this->signal->value;
    }
}
