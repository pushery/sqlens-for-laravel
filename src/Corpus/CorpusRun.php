<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;

/**
 * Turns one collection's findings into classified cases.
 *
 * ## The one rule that shapes everything here
 *
 * The measurement must use the SAME engine `sqlens:lint` uses. A second code path that "does
 * roughly the same analysis" would measure itself: it would drift from the shipped runner exactly
 * where the shipped runner is subtle, and it would drift silently, because both would keep passing
 * their own tests.
 *
 * So nothing in this class analyses anything. It receives the findings a real lint run produced and
 * lines them up against the ground truth. Everything above it — resolving migrations, capturing
 * statements, applying rules — is the shipped runner, unmodified.
 *
 * ## Why the lookup is per rule id rather than per finding
 *
 * A collection may produce several findings for one rule across several migrations, and the ground
 * truth speaks about the RULE. Reducing the findings to one outcome per rule is therefore the
 * comparison the corpus actually specified — and it has to be a reduction rather than a first-match,
 * because a rule that failed on one migration and passed on another has failed for this collection.
 */
final readonly class CorpusRun
{
    /**
     * Classify one collection against the findings a lint run produced for it.
     *
     * @param  list<Finding>  $findings  from the shipped runner, unmodified
     * @return list<array{rule_id: string, driver: string, level: int, classification: CorpusClassification}>
     */
    public static function classify(CorpusCollection $collection, array $findings, string $driver): array
    {
        $observed = self::worstPerRule($findings);
        $levels = self::levelPerRule($findings);

        $cases = [];

        foreach ($collection->expectations as $expectation) {
            $ruleId = $expectation['rule_id'];

            $cases[] = [
                'rule_id' => $ruleId,
                'driver' => $driver,
                // The level the finding carried, or 0 when the rule said nothing at all. A missing
                // level is not an unknown one: no finding means no level was reported, and putting
                // a guessed number in the per-level breakdown would move a bar nobody measured.
                'level' => $levels[$ruleId] ?? 0,
                'classification' => CorpusClassifier::classify($expectation['outcome'], $observed[$ruleId] ?? null),
            ];
        }

        return $cases;
    }

    /**
     * The most serious outcome each rule produced.
     *
     * A rule that failed on one migration of a collection and passed on another has FAILED for that
     * collection — taking the first finding would make the answer depend on file order, which is the
     * kind of non-determinism that produces a different rate on every machine.
     *
     * Ordering, most serious first: `fail` beats `undetermined` beats `pass`. `undetermined` sits in
     * the middle deliberately: it is not a failure, and it must not be swallowed by one either,
     * because a run that could not answer has to stay visible as such.
     *
     * @param  list<Finding>  $findings
     * @return array<string, Outcome>
     */
    private static function worstPerRule(array $findings): array
    {
        $worst = [];

        foreach ($findings as $finding) {
            $outcome = $finding->status->outcome;
            $current = $worst[$finding->ruleId] ?? null;

            if ($current === null || self::rank($outcome) > self::rank($current)) {
                $worst[$finding->ruleId] = $outcome;
            }
        }

        return $worst;
    }

    /**
     * The level each rule reported with.
     *
     * @param  list<Finding>  $findings
     * @return array<string, int>
     */
    private static function levelPerRule(array $findings): array
    {
        $levels = [];

        foreach ($findings as $finding) {
            $levels[$finding->ruleId] = $finding->level->value;
        }

        return $levels;
    }

    private static function rank(Outcome $outcome): int
    {
        return match ($outcome) {
            Outcome::Fail => 3,
            Outcome::Undetermined => 2,
            default => 1,
        };
    }
}
