<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

use Pushery\SQLens\Findings\Outcome;

/**
 * Turns one expectation plus what the rule set actually said into a classification.
 *
 * ## Why this is a pure function over data rather than something that runs a lint
 *
 * The measurement has to run against real PostgreSQL 18 and MySQL 8.4 servers to be worth anything,
 * and those runs are their own ticket. What must NOT differ between the two engines is the
 * classification: if PostgreSQL and MySQL disagreed about what counts as a false positive, the two
 * rates would not be comparable and neither would mean much.
 *
 * So the engine hands over findings, this decides, and it does so with no connection, no driver and
 * no filesystem. That also makes every cell of the grid testable in-process, which is what lets the
 * five classes each have a real arm rather than a comment.
 *
 * ## The grid, stated once
 *
 *                          | rule said FAIL   | rule said nothing | rule said UNDETERMINED
 *     ---------------------|------------------|-------------------|------------------------
 *     expected_fail        | true_positive    | false_negative    | undetermined_unexpected
 *     expected_pass        | false_positive   | true_positive     | undetermined_unexpected
 *     expected_undetermined| false_positive   | false_negative    | undetermined_expected
 *
 * Two cells deserve their reasoning written down.
 *
 * **`expected_pass` + silence is a TRUE POSITIVE, not an absence.** It is the tool correctly saying
 * nothing about good code, which is the behavior a false-positive measurement exists to reward. A
 * measurement that only counted the failures would have no denominator worth the name.
 *
 * **`expected_undetermined` + a hard fail is a FALSE POSITIVE.** The corpus said this case cannot be
 * decided; a rule that decided it anyway has asserted something it could not know. That is exactly
 * the guessing this package refuses, and it must cost the same as any other false alarm.
 */
final readonly class CorpusClassifier
{
    /**
     * Classify one expectation against the outcome the rule set produced for that rule.
     *
     * `$actual` is `null` when the rule said nothing at all — deliberately distinct from
     * `Outcome::Pass`, because a rule that ran and passed and a rule that never fired are the same
     * silence to a reader and different facts to a measurement.
     */
    public static function classify(string $expected, ?Outcome $actual): CorpusClassification
    {
        // Every unexpected `undetermined` lands here first, whatever was expected. It is neither a
        // false positive nor a pass: the case was not measured, and saying so is the point.
        if ($actual === Outcome::Undetermined && $expected !== 'expected_undetermined') {
            return CorpusClassification::UndeterminedUnexpected;
        }

        return match ($expected) {
            'expected_fail' => $actual === Outcome::Fail
                ? CorpusClassification::TruePositive
                : CorpusClassification::FalseNegative,

            // Silence over good code is the behavior being measured, so it is a true positive
            // rather than a non-event. `Outcome::Pass` and "nothing at all" are the same verdict
            // here — both mean the rule declined to complain.
            'expected_pass' => $actual === Outcome::Fail
                ? CorpusClassification::FalsePositive
                : CorpusClassification::TruePositive,

            // A rule that answered where the corpus says nobody can answer has asserted something it
            // could not know. That costs the same as any other false alarm.
            'expected_undetermined' => self::againstAnUndecidableCase($actual),

            // An expectation class the format does not know cannot be classified, and guessing one
            // would put a fabricated cell into a published rate. The loader refuses these before
            // they reach here; this is the second door.
            default => CorpusClassification::UndeterminedUnexpected,
        };
    }

    /**
     * The three answers to a case the corpus says cannot be decided.
     *
     * Its own method rather than a `match` nested inside a `match` arm, and the reason is
     * measurement rather than taste: pcov attributes the execution of a nested match to the arm's
     * opening line inconsistently, and the line showed as uncovered while three arms exercised it.
     * A coverage floor that cannot see a covered line is a floor that gets waived, so the code moved
     * instead of the floor.
     */
    private static function againstAnUndecidableCase(?Outcome $actual): CorpusClassification
    {
        if ($actual === Outcome::Undetermined) {
            return CorpusClassification::UndeterminedExpected;
        }

        if ($actual === Outcome::Fail) {
            return CorpusClassification::FalsePositive;
        }

        return CorpusClassification::FalseNegative;
    }
}
