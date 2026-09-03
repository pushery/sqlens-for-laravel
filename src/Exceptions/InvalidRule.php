<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * A rule is misconfigured in a way that is a programming error, not a runtime
 * degradation: it declares no suite, or two rules claim the same id. These are
 * bugs in a rule (ours or a third-party pack), so they fail loud and early — a
 * silent no-op here would make findings unresolvable or hide a rule from every
 * run.
 *
 * This is deliberately NOT how "a rule cannot evaluate a subject" is handled —
 * that is an undetermined finding with a named reason, never an exception.
 */
final class InvalidRule extends LogicException
{
    public static function withoutSuite(string $ruleId): self
    {
        return new self(sprintf(
            'Rule "%s" declares no suite; every rule must belong to at least one suite.',
            $ruleId,
        ));
    }

    public static function duplicateId(string $ruleId): self
    {
        return new self(sprintf(
            'Duplicate rule id "%s"; rule ids are public API and must be unique — never "last wins".',
            $ruleId,
        ));
    }
}
