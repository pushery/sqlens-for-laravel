<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Audit\IgnoreList;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;

/**
 * The audit's ignore list, expressed as a suppression the reporter shows rather than a silence.
 *
 * ## Why it is a suppression source and not a filter in the runner
 *
 * Because the two are indistinguishable in the code and opposite in the report. A runner that
 * dropped ignored findings before assembling the result would produce output identical to a clean
 * audit — same summary, same exit code, same "0 findings" — over a database with twelve known
 * problems. Routed through this machinery instead, every hidden finding is counted, listed with
 * the source that hid it, and reported as a number in the header. Suppression stays a statement
 * somebody made rather than a disappearance.
 *
 * That is also why the ignore list itself decides nothing: {@see IgnoreList} answers "does the
 * configuration name this rule on this object" and stops. This class is the only place the answer
 * becomes an effect.
 *
 * ## What it can reach
 *
 * A finding's object path comes from its {@see Location}, which the
 * catalog reader fills with the qualified name it read — so patterns are matched against what the
 * reader produced rather than against a raw catalog string, and quoting cannot decide a match.
 *
 * A finding with no object is reachable only by the rule-wide form, which is enforced inside the
 * ignore list. Those are the run-level notices — "no active rules", "the connection is pooled",
 * "part of the catalog could not be read" — and they are precisely the ones that say the run
 * itself was incomplete. An object pattern that swallowed one would hide the fact that the audit
 * did not happen.
 */
final readonly class AuditIgnoreSuppressionSource
{
    /** The suppression-source name a resolver records on a finding it hides. */
    public const string SOURCE = 'audit_ignore';

    public function __construct(private IgnoreList $ignore) {}

    /**
     * The suppression covering this finding, or null when the project named neither it nor its
     * object.
     *
     * The reason names the FORM that matched rather than the pattern, because a reader who wants
     * the pattern has the config open in front of them, while a reader who wants to know why a
     * finding is hidden is asking which decision covered it.
     */
    public function suppressionFor(Finding $finding): ?Suppression
    {
        $form = $this->ignore->matchedForm($finding->ruleId, $finding->location->objectName);

        if ($form === null) {
            return null;
        }

        return new Suppression(
            source: self::SOURCE,
            // The FORM is in the reason, so a report can be counted by it without a second field
            // that could disagree with this one. "12 suppressed" tells a reader something is
            // hidden; "9 by rule, 3 by object" tells them how it got that way, which is what
            // decides whether the list has grown past what anyone intended.
            reason: 'ignored by sqlens.audit.ignore ('.$form.')',
        );
    }
}
