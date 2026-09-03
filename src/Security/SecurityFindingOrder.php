<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Severity\Severity;

/**
 * The order a security report is read in: worst first.
 *
 * Every other suite here sorts by LOCATION — where it is, then which rule said it — because that is
 * how somebody works through a migration or a schema, top to bottom. A security report is not read
 * that way. It is triaged: what is the worst thing, and is there anything above the line I have to
 * act on today. A location-ordered security report puts a critical grant below an informational
 * naming remark because `public.accounts` sorts after `public.a_view`.
 *
 * ## Why the aggregate needs its own order at all
 *
 * `SecurityRunner` concatenates two already-sorted halves, and concatenation of two sorted lists is
 * not a sorted list. The result is deterministic — the same input always produces the same sequence
 * — but deterministic is not the same as ordered, and only one of the two is what a reader needs.
 *
 * ## What this deliberately does NOT do
 *
 * **Merge findings from different sources.** The plan asks for a lint finding about a
 * `GRANT … TO PUBLIC` migration and an audit finding about the resulting catalog state to become one
 * entry carrying both sources. Measured: it cannot be done today, and not for want of effort.
 * `Location::inMigration()` takes no object name and leaves the field null, so a migration finding
 * does not know WHICH object its statement touches. The only thing the two findings share is a rule
 * id — and merging on a rule id alone is exactly the wrong merge the plan's own guard rail forbids:
 * two different tables, one rule, collapsed into a single entry that is true of neither.
 *
 * So the merge waits for the capture layer to attach the object it already parses, and this file
 * does the half that stands on its own.
 */
final readonly class SecurityFindingOrder
{
    /**
     * Sort worst-first, with every tie broken by something stable.
     *
     * Three keys, and each earns its place:
     *
     * 1. **Severity descending.** The triage question, answered first.
     * 2. **Rule id.** So two findings of one weight group by what they are about rather than
     *    interleaving.
     * 3. **The location's own sort key.** The last resort, and the one that makes the order total:
     *    without it two findings sharing a rule and a severity could swap between runs, and every
     *    golden report in this repository would become a coin toss.
     *
     * A finding with no severity — a safety or performance rule that reached this report through a
     * category the run did not narrow away — sorts below every weighted one rather than above. It is
     * not on the risk axis, so claiming a place among the weights would be inventing one.
     *
     * @param  list<Finding>  $findings
     * @return list<Finding>
     */
    public static function sorted(array $findings): array
    {
        usort($findings, static fn (Finding $a, Finding $b): int => [
            -self::weight($a), $a->ruleId, $a->location->sortKey(),
        ] <=> [
            -self::weight($b), $b->ruleId, $b->location->sortKey(),
        ]);

        return $findings;
    }

    /**
     * A finding's place on the risk axis, as a number this order can compare.
     *
     * `-1` for a finding that carries no severity, so it lands below `info` rather than beside it.
     * Zero would put it level with the lowest real weight and let the rule id decide between "we
     * measured this as the least severe thing here" and "this was never weighed at all".
     */
    private static function weight(Finding $finding): int
    {
        return $finding->severity instanceof Severity ? $finding->severity->rank() : -1;
    }
}
