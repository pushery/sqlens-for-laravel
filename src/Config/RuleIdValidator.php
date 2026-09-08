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
 * ⚠️ That sentence was a PROMISE rather than a description until 2026-09-08, and the gap ran the
 * expensive way. Measured then: `inConfigIgnore` was reached by `sqlens:agent-rules` alone — a
 * command a project may never run — and `inAnnotation` by nothing at all. So in a lint run, the
 * suite that fires on every migration, two of the three forms went unchecked.
 *
 * All three are checked now, and the ANSWER differs by form because the text lives in different
 * places. An ignore list and a baseline are edited by whoever runs the tool today, so an unknown id
 * there is a refusal. An annotation sits in a migration that shipped years ago and will never be
 * touched again — refusing over a rule renamed since would turn a project's history into a timer,
 * so that form is reported as a notice and the run continues.
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
     * @param  list<string>  $openNamespaces  finding-id prefixes owned by an external tool, DERIVED
     *                                        from `Driver::tools()` rather than listed. An id under
     *                                        one of them is accepted even when this build does not
     *                                        describe the rule — and reported, never silently. See
     *                                        {@see undescribedToolRules()} for why both halves are
     *                                        needed.
     */
    public function __construct(
        private RuleRegistry $registry,
        private array $alsoKnown = [],
        private array $openNamespaces = [],
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
            // An id inside a tool's own namespace is ACCEPTED here and reported by
            // {@see undescribedToolRules()} instead. A project must be able to name a rule its
            // installed binary emits without waiting for a release of this package to describe it
            // — and the alternative it had was freeing the whole `tool_rule_unmapped` bucket,
            // which also frees the locking rules the tool is installed for.
            if ($this->inOpenNamespace($reference->ruleId)) {
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
     * The references naming a tool rule this build does not describe — accepted, and SAID.
     *
     * ## Why accepting silently would have been the wrong fix
     *
     * The refusal this replaces exists against the most expensive misconfiguration there is: a typo
     * that leaves the rule firing while somebody believes it is off. Simply letting every
     * `SQUAWK.*` string through would hand that failure back under a friendlier name — and a tool
     * namespace is exactly where a typo is likeliest, because the ids are somebody else's and this
     * build cannot spell-check them.
     *
     * So the third state this package uses everywhere else: not valid, not refused, but accepted
     * and named. The notice fires on every run and deterministically — it needs no run that would
     * have produced the finding, which makes it stronger than an "this ignore never matched"
     * report could be.
     *
     * ## The set is exactly what `unknown()` stopped flagging
     *
     * The two partitions are complementary by construction: an id is either described, or inside a
     * tool namespace and reported here, or unknown and refused there. Nothing falls between them,
     * and nothing is counted twice.
     *
     * @param  list<RuleIdReference>  $references
     * @return list<string> one human-readable notice per undescribed tool id
     */
    public function undescribedToolRules(array $references): array
    {
        $notices = [];

        foreach ($references as $reference) {
            if ($this->registry->get($reference->ruleId) instanceof Rule) {
                continue;
            }
            if (in_array($reference->ruleId, $this->alsoKnown, true)) {
                continue;
            }
            if (! $this->inOpenNamespace($reference->ruleId)) {
                continue;
            }

            $notices[] = sprintf(
                '%s names %s, a rule this build does not describe. It is accepted: the id belongs to '
                .'an external tool, and a project must be able to name what its installed binary '
                .'emits without waiting for a release here. It will match only if the tool reports '
                .'that exact name — so if nothing changes, check the spelling against the tool.',
                $reference->describe(),
                $reference->ruleId,
            );
        }

        return $notices;
    }

    /**
     * Whether the id sits inside a namespace an external tool owns.
     *
     * A prefix match rather than an exact one, which is the entire capability: the point is to
     * accept ids this build has never heard of.
     */
    private function inOpenNamespace(string $ruleId): bool
    {
        return array_any($this->openNamespaces, fn (string $namespace): bool => $namespace !== '' && str_starts_with($ruleId, $namespace));
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
