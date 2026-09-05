<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A considered `none` for a catalog rule, attached only where the rule itself FLAGGED.
 *
 * ## Why the guard reuses the rule's own judgment
 *
 * `ProvidesSchemaObjectRemediation` states its precondition in prose — a rule is asked only about an
 * object it reported on — and prose is what the lint side proved a type cannot replace. But a
 * SECOND copy of a rule's own applicability test, written here to be safe, is the other classic
 * failure: two conditions for one question, and the day a rule narrows its subject the copy keeps
 * answering about objects the rule has stopped flagging.
 *
 * So this asks the rule. `judgeSchemaObject()` is already the authority on whether an object is this
 * rule's business, and asking twice is cheap — a catalog rule reads attributes off an object it was
 * handed, with no database and no clock behind it.
 *
 * ## And only a FAIL, never an undetermined or a pass
 *
 * An undetermined verdict is a rule declining to answer. Material beside it would overtake the
 * verdict — "here is what to do about the thing I just said I could not decide" — which is the one
 * way a fix template is worse than none at all.
 */
trait OffersAConsideredNone
{
    /** The reason key naming WHY there is no standard sequence for this rule's finding. */
    abstract protected function noSequenceReasonKey(): string;

    /** How a reader confirms whatever they decide — the same answer for every state finding. */
    protected function noSequenceVerificationKey(): string
    {
        return 'sqlens::messages.remediation.no_safe_sequence.schema_decision_state_verification';
    }

    public function remediationForObject(SchemaObject $object): ?RemediationPayload
    {
        $flagged = array_filter(
            $this->judgeSchemaObject($object),
            static fn (RuleVerdict $verdict): bool => ! $verdict->isPass
                && ! $verdict->isUndetermined()
                && ! $verdict->notApplicableReason instanceof NotApplicableReason,
        );

        if ($flagged === []) {
            return null;
        }

        return new NoSafeSequenceTemplate()->payload(
            $this->noSequenceReasonKey(),
            $this->noSequenceVerificationKey(),
            $this->id(),
            // No downtime class: there is no deploy here whose effect one could describe, and the
            // validator refuses a state payload that carries one.
            null,
            RemediationSubject::SchemaObject,
        );
    }
}
