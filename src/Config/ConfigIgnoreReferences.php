<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

use Pushery\SQLens\Reporting\Suppression\ConfigIgnoreRule;

/**
 * The rule ids a project wrote into `sqlens.ignore`, as references a validator can check.
 *
 * ## Why this is its own class and not a method on either caller
 *
 * Two runs read the same list and must reach the same verdict about it: `sqlens:agent-rules`
 * refuses a catalog built over an unknown id, and `sqlens:lint` refuses a run. Written twice, the
 * two would agree for a long time and then disagree once — about which entry counts as scoped,
 * about what a malformed row means — and the disagreement would be invisible, because each half
 * looks right on its own.
 *
 * So the reading lives here and the DECISION stays with each caller. What to do about a violation
 * is a property of the run; what the file says is not.
 *
 * ## The index is the entry's identity
 *
 * Two entries can be byte-identical, and "the ignore at position 3 names a rule that does not
 * exist" is what lets somebody find and delete the line. That is the same reason
 * {@see ConfigIgnoreRule} carries one.
 *
 * ## A malformed row is skipped rather than refused, and that is not leniency
 *
 * The config schema validates the SHAPE of this list before any run starts, so a row without a
 * `rule` key has already been refused with a message about its shape. Refusing it a second time
 * here would replace "this entry is malformed" with "its rule id is unknown" — the less useful
 * half of the same news, arriving first. The same reading the resolver has always given it.
 */
final readonly class ConfigIgnoreReferences
{
    /**
     * @param  mixed  $configured  the raw `sqlens.ignore` value
     * @return list<RuleIdReference>
     */
    public static function of(mixed $configured): array
    {
        if (! is_array($configured)) {
            return [];
        }

        $references = [];

        foreach (array_values($configured) as $index => $entry) {
            if (! is_array($entry)) {
                continue;
            }

            if (! is_string($entry['rule'] ?? null)) {
                continue;
            }

            $references[] = RuleIdReference::inConfigIgnore($entry['rule'], $index);
        }

        return $references;
    }
}
