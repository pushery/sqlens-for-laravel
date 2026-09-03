<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;

/**
 * A considered `none` — the payload a rule produces when it has looked and there IS no safe
 * standard sequence.
 *
 * ## Why this is a type rather than a shrug
 *
 * `strategy: none` and an absent payload are different facts. An absent payload says only that
 * nobody wrote a template; a `none` payload says a rule examined this statement and concluded there
 * is nothing standard to recommend. A reader acts differently on each — and the difference is worth
 * nothing unless the `none` carries a REASON.
 *
 * That is the whole job here: a `none` without a reason is a shrug wearing a contract's clothes, and
 * this class makes the reason structurally unskippable — the note key is a required argument.
 *
 * ## Why it still carries a step
 *
 * A `none` with no steps at all reads, in a report, exactly like a payload somebody forgot to fill
 * in. So it carries exactly one, and that step is a {@see RemediationStepKind::ManualGate} — which
 * is honest rather than decorative: there is no sequence to run, and what remains is a decision
 * somebody has to make. The gate is that decision, named.
 *
 * ## What it must never become
 *
 * A convenient answer. `none` is for the statement whose remedy genuinely is not standard — a
 * `TRUNCATE` in a migration is a team's call about their data, not a pattern. A rule that reached
 * for this because writing a template was work would be using a considered conclusion to describe
 * an absence, which is the one distinction the field exists to preserve.
 */
final readonly class NoSafeSequenceTemplate
{
    /**
     * The considered `none`.
     *
     * @param  string  $reasonKey  the translation key naming WHY there is no standard sequence.
     *                             Required, and required as an argument rather than defaulted:
     *                             a default would make the reason forgettable, which is the only
     *                             failure this class exists to prevent.
     * @param  string  $verificationKey  how a reader confirms whatever they decide
     */
    public function payload(string $reasonKey, string $verificationKey, string $ruleId, ?DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: $reasonKey,
                ),
            ],
            strategy: RemediationStrategy::None,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            verification: $verificationKey,
        );
    }
}
