<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

/**
 * The `SQUAWK.*` rule ids a project may legitimately name in a suppression.
 *
 * Declared from the shipped map, never from a running binary, and that is the whole decision.
 * A project that ignores `SQUAWK.ban-char-field` has written a correct configuration; if the
 * validator asked the binary, that same file would be a misconfiguration on a laptop without
 * the tool, on Windows where it has no build, and on any run with the tool switched off. The
 * configuration says what the project MEANS, and a machine's inventory is not a vote on it.
 *
 * The set is narrower than the map on purpose: a rule SQLens deliberately does not report can
 * never produce a finding, so a suppression naming it would suppress nothing — which is exactly
 * the "no silent no-op" this package refuses everywhere else.
 */
final readonly class SquawkRuleIds
{
    /**
     * @return list<string> every id that can actually appear in a report, sorted
     */
    public static function suppressible(): array
    {
        $ids = [];

        foreach (SquawkRuleMap::bundled()->rules() as $rule) {
            if (SquawkRuleMap::bundled()->for($rule)?->surfaces() === true) {
                $ids[] = SquawkFindingMapper::ID_PREFIX.$rule;
            }
        }

        sort($ids);

        return $ids;
    }
}
