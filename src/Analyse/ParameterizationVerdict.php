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
        /**
         * Every runtime part of the text went through the engine's identifier quoting.
         *
         * It rides on an INTERPOLATED verdict and changes nothing about it — the signal stays
         * `interpolated`, because a quoted identifier is still a runtime value in the statement's
         * text and can still choose which object the statement addresses. What it changes is the
         * ADVICE a rule can give: "pass it as a binding" is impossible at an identifier position,
         * and a rule that says it anyway reads as one that did not understand the code.
         *
         * False by default and false for every other signal, which is the honest reading: a
         * parameterized statement has nothing to quote, and an undetermined one is a statement the
         * classifier could not see.
         */
        public bool $identifierQuoted = false,
    ) {}

    /** The SQL text is fully known at analysis time — no runtime value reaches the statement's shape. */
    public static function parametrized(FragmentOrigin $origin): self
    {
        return new self(ParametrizationSignal::Parametrized, $origin, null);
    }

    /**
     * Something non-constant was visibly assembled into the SQL text.
     *
     * `$identifierQuoted` says the assembly went through `Grammar::wrap()`. It does NOT soften the
     * verdict — see the property for why — it only lets a rule downstream give advice that can be
     * followed.
     */
    public static function interpolated(FragmentOrigin $origin, bool $identifierQuoted = false): self
    {
        return new self(ParametrizationSignal::Interpolated, $origin, null, $identifierQuoted);
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
