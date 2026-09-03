<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

/**
 * Whether the page a finding's documentation URL names has been written yet.
 *
 * The state exists so that "no page" is a NAMED value in the registry export rather than an
 * absence. An absence is unreadable in both directions: a completeness check cannot count what
 * is not there, and a maintainer looking at the export cannot tell a rule whose page is still
 * to be written from a rule that was never exported at all.
 *
 * That is the same three-valued discipline the findings themselves follow — a check that could
 * not run reports `undetermined` with a reason, never a pass. A link that goes nowhere is the
 * documentation's version of a silent green: it looks exactly like a link that works.
 */
enum RuleDocumentationState: string
{
    /** The page exists. */
    case Published = 'published';

    /** The URL is derived and stable, but nobody has written the page behind it yet. */
    case Pending = 'pending';
}
