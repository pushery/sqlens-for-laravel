<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

/**
 * What one comparison of a finding against its ground truth turned out to be.
 *
 * ## Five classes rather than two, and the last two are the reason
 *
 * A false-positive measurement wants to say "the tool complained about code that was fine". Reduced
 * to right-and-wrong, three quite different things collapse into one:
 *
 * - A rule that fired where the corpus said it should is a **true positive** — the control that
 *   keeps the whole measurement honest, because a rule set that reported NOTHING would otherwise
 *   score a perfect false-positive rate.
 * - A rule that stayed quiet where the corpus expected a finding is a **false negative**. It is not
 *   a false positive and must not improve the number; it is the opposite failure and its own count.
 * - A rule that answered `undetermined` where the corpus EXPECTED that is
 *   {@see self::UndeterminedExpected} — correct behavior, and counting it as a false positive
 *   would punish a rule for honestly reporting it could not run.
 * - A rule that answered `undetermined` where the corpus expected an answer is
 *   {@see self::UndeterminedUnexpected}. This is the class the ticket insists on: it is **neither**
 *   a false positive **nor** a pass. It means the measurement could not be made for that case, and
 *   a run full of them is a run whose rate describes less than it appears to.
 *
 * Folding either undetermined class into pass or fail would produce a number that looks the same
 * and means something else, which is the failure mode this package refuses everywhere.
 */
enum CorpusClassification: string
{
    /** The corpus expected a finding and got one. */
    case TruePositive = 'true_positive';

    /** The corpus expected silence and got a finding — the number this measurement is about. */
    case FalsePositive = 'false_positive';

    /** The corpus expected a finding and got silence. The opposite failure, counted apart. */
    case FalseNegative = 'false_negative';

    /** The corpus expected `undetermined` and got it. Correct, and deliberately not a failure. */
    case UndeterminedExpected = 'undetermined_expected';

    /** An `undetermined` nobody expected. Not a pass, not a false positive — a case not measured. */
    case UndeterminedUnexpected = 'undetermined_unexpected';

    /**
     * Whether this class means the case was actually measured.
     *
     * Used to report the measured fraction beside the rate. A rate over 40 of 200 cases is a
     * different claim from the same rate over 200 of 200, and a report that printed only the
     * percentage would make them look identical.
     */
    public function measured(): bool
    {
        return $this !== self::UndeterminedUnexpected;
    }

    /**
     * Whether this class counts against the tool.
     *
     * `UndeterminedUnexpected` is deliberately absent: it is a gap in the measurement rather than a
     * defect in a rule, and putting it here would let a run improve its own rate by becoming less
     * able to answer.
     */
    public function isDefect(): bool
    {
        return $this === self::FalsePositive || $this === self::FalseNegative;
    }
}
