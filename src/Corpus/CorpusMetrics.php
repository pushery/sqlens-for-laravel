<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

/**
 * The numbers a corpus run produces.
 *
 * ## Why the rate is never printed alone
 *
 * A false-positive rate is a fraction, and a fraction hides two things a reader needs: how many
 * cases it was computed over, and how many cases could not be computed at all. Both move it, and
 * neither is visible in the percentage.
 *
 * The failure this guards against is specific. Every way a corpus run can go wrong — a rule that
 * cannot read a catalog, a missing binary, a version outside a window — produces `undetermined`, and
 * `undetermined` cases leave the denominator. So a run that got WORSE at answering reports a BETTER
 * rate, and nothing in the number says so. That is why {@see self::$unmeasured} sits beside the rate
 * rather than inside it, and why the blind spots are counted rather than dropped.
 *
 * ## Per rule, per driver, per level
 *
 * An aggregate rate over a rule set is close to meaningless for acting on: one noisy rule at 40%
 * disappears into ninety quiet ones. The breakdowns are what make a number actionable, and the
 * `blindSpots` list is what stops a high score over a narrow slice from reading as coverage.
 */
final readonly class CorpusMetrics
{
    /**
     * @param  array<string, int>  $counts  classification value => how many
     * @param  array<string, array<string, int>>  $byRule  rule id => counts
     * @param  array<string, array<string, int>>  $byDriver  driver => counts
     * @param  array<int, array<string, int>>  $byLevel  level => counts
     * @param  list<string>  $blindSpots  rules the corpus never exercised
     */
    private function __construct(
        public array $counts,
        public array $byRule,
        public array $byDriver,
        public array $byLevel,
        public array $blindSpots,
    ) {}

    /**
     * Aggregate a run's classified cases.
     *
     * @param  list<array{rule_id: string, driver: string, level: int, classification: CorpusClassification}>  $cases
     * @param  list<string>  $allRuleIds  every rule the build ships, so blind spots are derivable
     */
    public static function of(array $cases, array $allRuleIds): self
    {
        $counts = self::emptyCounts();
        $byRule = [];
        $byDriver = [];
        $byLevel = [];

        foreach ($cases as $case) {
            $key = $case['classification']->value;

            $counts[$key]++;

            $byRule[$case['rule_id']] ??= self::emptyCounts();
            $byRule[$case['rule_id']][$key]++;

            $byDriver[$case['driver']] ??= self::emptyCounts();
            $byDriver[$case['driver']][$key]++;

            $byLevel[$case['level']] ??= self::emptyCounts();
            $byLevel[$case['level']][$key]++;
        }

        // Sorted at the point of construction rather than at the point of rendering: two runs over
        // one corpus must produce byte-identical output, and a hash map's order is not a contract.
        ksort($byRule);
        ksort($byDriver);
        ksort($byLevel);

        $exercised = array_keys($byRule);
        $blindSpots = array_values(array_diff($allRuleIds, $exercised));
        sort($blindSpots);

        return new self($counts, $byRule, $byDriver, $byLevel, $blindSpots);
    }

    /**
     * The false-positive rate over the cases that could be measured, or null when none could.
     *
     * **Null rather than zero**, and the difference is the whole point: zero reads as "no false
     * positives", which is the best possible result. A run that measured nothing would then report
     * the same number as a flawless one.
     */
    public function falsePositiveRate(): ?float
    {
        $measured = $this->measured();

        if ($measured === 0) {
            return null;
        }

        return $this->counts[CorpusClassification::FalsePositive->value] / $measured;
    }

    /** How many cases were actually measured. */
    public function measured(): int
    {
        $measured = 0;

        foreach (CorpusClassification::cases() as $class) {
            if ($class->measured()) {
                $measured += $this->counts[$class->value];
            }
        }

        return $measured;
    }

    /**
     * How many cases could NOT be measured.
     *
     * Reported beside the rate, never folded into it. Every failure mode of a corpus run lands here,
     * and every one of them would otherwise IMPROVE the rate by shrinking its denominator.
     */
    public function unmeasured(): int
    {
        return $this->counts[CorpusClassification::UndeterminedUnexpected->value];
    }

    /** @return array<string, int> */
    private static function emptyCounts(): array
    {
        $counts = [];

        foreach (CorpusClassification::cases() as $class) {
            $counts[$class->value] = 0;
        }

        return $counts;
    }
}
