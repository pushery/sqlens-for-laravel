<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

/**
 * What the version axis decided about one rule, in the audit context.
 *
 * Three values, and the third is why this is an enum instead of a boolean. "Runs" and "does not
 * run" would collapse two very different situations into one: a rule deliberately not written for
 * this server, and a rule nobody could judge because the server's version is unknown. The first is
 * correct silence; the second is an answer the run does not have — and reporting them the same way
 * is how a level gate quietly shrinks without anyone noticing.
 */
enum AuditVersionVerdict: string
{
    /** The version is known and the rule's window includes it: the rule runs. */
    case Applicable = 'applicable';

    /**
     * The version is known and the rule's window excludes it: the rule does NOT run, and that is
     * correct rather than a gap. It is still named, so a shrinking rule set stays visible.
     */
    case Gated = 'gated';

    /**
     * The version is not known and the rule depends on one. Never a pass: a rule that cannot be
     * judged has not been judged, and guessing against a default version is the mistake this whole
     * axis exists to prevent.
     */
    case Undetermined = 'undetermined';
}
