<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Levels\Level;

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
 * So nothing in this class analyzes anything. It receives the findings a real lint run produced and
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
     * The level a corpus measurement runs at: the highest one there is.
     *
     * The rate is a claim about the whole rule pack. A run at the level a host application happens to
     * configure leaves every rule above that level silent, and the classifier would book the silence
     * as a false negative where the corpus expects a failure and as a correct silence where it expects
     * none. Both would be verdicts about rules that never ran.
     *
     * The measurement command and the real-engine lane read this one value, so the report and the
     * test that holds it cannot drift onto two different levels.
     */
    public static function measuredLevel(): int
    {
        return max(array_map(static fn (Level $level): int => $level->value, Level::cases()));
    }

    /**
     * Classify one collection against the findings a lint run produced for it.
     *
     * @param  list<Finding>  $findings  from the shipped runner, unmodified
     * @param  array<string, int>  $declaredLevels  rule id => the level the shipped rule registry declares for it
     * @return list<array{rule_id: string, driver: string, level: int, classification: CorpusClassification}>
     */
    public static function classify(CorpusCollection $collection, array $findings, string $driver, array $declaredLevels = []): array
    {
        $observed = self::worstPerRule($findings);
        $levels = self::levelPerRule($findings);

        $cases = [];

        foreach ($collection->expectations as $expectation) {
            $ruleId = $expectation['rule_id'];

            $cases[] = [
                'rule_id' => $ruleId,
                'driver' => $driver,
                // The level the rule DECLARES, whether or not it spoke in this run. A silent rule has
                // a level too: a level-8 naming rule that correctly says nothing is still a level-8
                // case, and filing it under level 0 would put it in the breakdown of the capture
                // layer. Only a rule the registry does not know falls back to the level its finding
                // carried, and to 0 when there was no finding either.
                'level' => $declaredLevels[$ruleId] ?? $levels[$ruleId] ?? 0,
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
