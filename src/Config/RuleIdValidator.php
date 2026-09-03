<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Rules\RuleDeprecation;
use Pushery\SQLens\Rules\RuleRegistry;

/**
 * Checks every rule id a project wrote into a suppression — the ignore list, the
 * baseline, and the `#[SqlensIgnore]` annotations — against the rules that
 * actually exist.
 *
 * This closes the single most expensive misconfiguration there is. A typo in an
 * ignored rule id means the rule keeps firing while the user believes it is off;
 * they then read past its findings for months. So an id no rule answers to is an
 * ERROR, with the spot it was written and the closest real id as a suggestion.
 *
 * The suggestion is offered, never applied. Rule ids are public API from 1.0 on,
 * so the comparison is EXACT: no case folding, no prefix guessing, no "did you
 * mean" that silently resolves. A validator that helpfully accepted
 * `pg.l2.concurrently` would make the id set unknowable, and the next release
 * that changed the folding would silently un-suppress findings.
 *
 * A DEPRECATED id is a notice, not an error. Governance says rules are deprecated
 * and never deleted, so a suppression naming one is still meaningful — it just
 * points at something on its way out, and the notice says what replaced it.
 */
final readonly class RuleIdValidator
{
    /**
     * @param  list<string>  $alsoKnown  ids that are real without a Rule object behind them —
     *                                   today, the external tools' namespaces. They are declared
     *                                   from the shipped map rather than from a running binary,
     *                                   and that is the entire point: a suppression naming a
     *                                   tool rule must stay valid on a machine where the tool is
     *                                   not installed, is switched off, or has no build for the
     *                                   platform. Reading the binary would make a correct
     *                                   configuration a misconfiguration on a laptop.
     */
    public function __construct(
        private RuleRegistry $registry,
        private array $alsoKnown = [],
    ) {}

    /**
     * @param  list<RuleIdReference>  $references
     * @return list<ConfigViolation> empty when every id is known
     */
    public function unknown(array $references): array
    {
        $violations = [];

        foreach ($references as $reference) {
            if ($this->registry->get($reference->ruleId) instanceof Rule) {
                continue;
            }
            if (in_array($reference->ruleId, $this->alsoKnown, true)) {
                continue;
            }
            $violations[] = ConfigViolation::unknownRuleId(
                $reference->describe(),
                $reference->ruleId,
                $this->closest($reference->ruleId),
            );
        }

        return $violations;
    }

    /**
     * The deprecated ids among the references, each with what replaced it. Not a
     * violation: a suppression naming a deprecated rule still means something.
     *
     * @param  list<RuleIdReference>  $references
     * @return list<string> one human-readable notice per deprecated reference
     */
    public function deprecationNotices(array $references): array
    {
        $notices = [];

        foreach ($references as $reference) {
            $rule = $this->registry->get($reference->ruleId);
            $deprecation = $rule?->deprecation();

            if (! $deprecation instanceof RuleDeprecation) {
                continue;
            }

            $notices[] = sprintf(
                '%s in %s is deprecated since %s%s.',
                $reference->ruleId,
                $reference->describe(),
                $deprecation->since,
                $deprecation->replacedBy === null ? '' : ', replaced by '.$deprecation->replacedBy,
            );
        }

        return $notices;
    }

    /**
     * The registered id closest to the given one, or null when nothing is close
     * enough to be worth suggesting.
     *
     * The distance ceiling matters: an unbounded "closest" match would confidently
     * suggest a completely unrelated rule for a wholly invented id, which is worse
     * than admitting there is no suggestion. Ties are broken by the id itself so
     * the message is deterministic.
     */
    private function closest(string $ruleId): ?string
    {
        $best = null;
        $bestDistance = PHP_INT_MAX;
        $ceiling = max(3, (int) floor(strlen($ruleId) / 3));

        // Both sets, because a typo in a tool rule id deserves the same help as a typo in ours —
        // and a suggestion drawn only from our own rules would answer `SQUAWK.ban-drop-tabel`
        // with a PostgreSQL rule id, which is confidently unhelpful.
        $candidates = [
            ...array_map(static fn (Rule $rule): string => $rule->id(), $this->registry->all()),
            ...$this->alsoKnown,
        ];

        foreach ($candidates as $candidate) {
            $distance = levenshtein($ruleId, $candidate);

            if ($distance < $bestDistance || ($distance === $bestDistance && $best !== null && strcmp($candidate, $best) < 0)) {
                $best = $candidate;
                $bestDistance = $distance;
            }
        }

        return $bestDistance <= $ceiling ? $best : null;
    }
}
