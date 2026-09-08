<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * A rule that can tell when its OWN configuration has left it unable to report.
 *
 * ## The gap this closes, and why no other layer could
 *
 * The four selection axes — level, category, stability, version window — decide whether a rule is
 * in the catalog at all, and a rule they drop is simply absent. This is a fifth state they cannot
 * express: the rule is admitted, it will be constructed, it will be asked, and it will answer
 * nothing under every input, because a switch inside its own configuration is off.
 *
 * From outside, that rule is indistinguishable from one that is watching. Preventive guidance built
 * from the catalog therefore tells an agent a convention is covered when nothing covers it — the
 * expensive direction, because the reader stops checking.
 *
 * ## Only a rule that KNOWS may implement this
 *
 * The reach of a switch is a property of the rule that reads it, and nothing else can derive it
 * without modeling every configuration key in the package. A second model would agree for a while
 * and then be confidently wrong about one rule — worse than the silence it replaced. So a rule
 * implements this when its own configuration can silence it, and the answer comes from the same
 * policy object its verdict comes from. A rule that does not implement it is not claimed to be
 * reachable; it is unexamined on this axis, which is a different and honest thing.
 *
 * ## The reason is prose, because it is read by a person or an agent
 *
 * A boolean would say "this is off" and leave the reader to find the switch. The string names it,
 * so the sentence that appears in a generated context file is actionable rather than merely
 * discouraging.
 */
interface DeclaresConfigurationReach
{
    /**
     * Why this rule cannot report under the configuration it was built with — null when nothing
     * has silenced it.
     *
     * A short phrase naming the switch, not a sentence: renderers put it inline behind a rule id,
     * and each of the three agent formats punctuates its own line.
     */
    public function silencedByConfiguration(): ?string;
}
