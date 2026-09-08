<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use Pushery\SQLens\Config\ConfigViolation;
use Pushery\SQLens\Config\RuleIdReference;
use Pushery\SQLens\Config\RuleIdValidator;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Rules\RuleRegistry;

/**
 * Every rule id a baseline names, checked against the rules that exist.
 *
 * ## Why an unvalidated baseline is worse than an unvalidated ignore list
 *
 * Both can carry an id that names nothing — a typo in a hand edit, or a rule renamed between two
 * releases. In an ignore list the mistake announces itself: the finding somebody meant to silence
 * keeps appearing, so they look again.
 *
 * A baseline fails the other way round. Its entries suppress findings that already existed, so an
 * entry that matches nothing produces exactly what a correctly matching one produces on a repaired
 * codebase: nothing. The line stays in the file, reads as a decision somebody made, and protects
 * nothing at all. Nobody finds that by looking at output, because the output is identical.
 *
 * ## A class rather than a method on the audit runner
 *
 * The lint suite reads its own baseline through the same {@see ConfiguredBaseline::forRun()} and
 * needs the same check; it does not have it yet, because its command refuses a run before this point
 * for reasons a test environment cannot get past, and a guard nobody can prove reaches its subject is
 * a guard that is not there. Kept as its own class so the second caller is a line rather than a
 * second copy of this walk.
 */
final readonly class BaselineRuleIds
{
    /**
     * The violations this baseline carries, or an empty list when every id it names is real.
     *
     * Checked against EVERY rule of every driver rather than the ones this run would use: a
     * baseline is written once and read on every machine, and an id that names a real rule from
     * another engine is a different mistake from one that names nothing. The external tools'
     * declared ids count as known for the same reason they do in an ignore list — a suppression
     * naming a tool rule has to stay valid on a machine where the tool is absent.
     *
     * @param  array<string, Rule>  $rules  every rule of every driver, for the near-miss suggestion
     * @param  list<string>  $openNamespaces  the tools' finding-id prefixes. A baseline is WRITTEN
     *                                        by this package from what a run found, so it can
     *                                        legitimately carry a tool id the shipped map does
     *                                        not describe — refusing it here would make the
     *                                        baseline command produce a file the next run
     *                                        rejects.
     * @return list<ConfigViolation>
     */
    public static function violations(BaselineFile $baseline, array $rules, array $openNamespaces = []): array
    {
        $emittable = EmittableIds::shipped();

        // A set that failed to load looks exactly like one in which every id is unknown, and acting
        // on the second reading would refuse every baseline on earth. So an empty set judges
        // nothing.
        if ($baseline->isEmpty() || $emittable->isEmpty()) {
            return [];
        }

        $references = array_map(
            // The entry KEY, not its index: a baseline is sorted deterministically, so an index
            // moves whenever an unrelated entry is added and the message would point at a
            // different line than the one it is about.
            static fn (BaselineEntry $entry): RuleIdReference => RuleIdReference::inBaseline(
                $entry->ruleId,
                $entry->key(),
            ),
            // Only the entries the shipped id set does not already account for. A family row —
            // `AUDIT.CATALOG.UNREAD` stands for `AUDIT.CATALOG.UNREAD.<reason>` — is a prefix rather
            // than an id, which is a question the validator's exact-match list cannot answer.
            array_values(array_filter(
                $baseline->entries,
                static fn (BaselineEntry $entry): bool => ! $emittable->knows($entry->ruleId),
            )),
        );

        // The rules are still passed as the registry, so a near miss on a RULE id gets its "did you
        // mean" suggestion — the shipped set is the wider net, not a replacement for the closer one.
        return new RuleIdValidator(RuleRegistry::fromRules($rules), $emittable->all(), $openNamespaces)
            ->unknown($references);
    }
}
