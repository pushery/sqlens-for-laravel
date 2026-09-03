<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * How firmly a rule can stand behind its own verdict.
 *
 * A deterministic rule reads the captured SQL and knows. A heuristic one reasons from
 * a pattern that is usually right and sometimes is not — an `UPDATE` with a wide
 * predicate probably touches many rows, but whether the surrounding code chunks it is
 * not in the SQL. Both produce a verdict; only one of them can be proven from what was
 * captured.
 *
 * **This is NOT `undetermined`.** An undetermined finding means the check could not
 * run — no server version, no statistics reader, an unparseable migration — and the
 * honest answer is "I do not know". A heuristic finding is the opposite situation: the
 * check ran and reached a conclusion, and the conclusion carries a margin. Collapsing
 * the two would either hide real findings behind "could not check" or dress up a guess
 * as a certainty, and both are the silent green this package exists to refuse.
 *
 * The value is public API from 1.0 on: `confidence` and its two strings are part of the
 * JSON contract, and only the prose around them is translatable.
 */
enum Confidence: string
{
    case Deterministic = 'deterministic';

    case Heuristic = 'heuristic';

    public function isHeuristic(): bool
    {
        return $this === self::Heuristic;
    }

    /**
     * The sentence a heuristic finding carries, or null for a deterministic one.
     *
     * It lives here, once, rather than in each heuristic rule's message. A rule that
     * phrased its own caveat would phrase it slightly differently from the next one,
     * and a reader comparing two findings could not tell whether the difference in
     * wording meant a difference in certainty. One sentence, one meaning.
     */
    public function honestyNote(): ?string
    {
        return match ($this) {
            self::Deterministic => null,
            self::Heuristic => 'Heuristic: this reads a pattern in the captured SQL and cannot be proven from it alone.',
        };
    }
}
