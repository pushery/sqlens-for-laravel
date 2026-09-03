<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * What a rule concluded about one statement: a FLAG (the statement is unsafe, with a
 * message), an UNDETERMINED (the rule could not decide, with a named reason and a
 * message), a NOT-APPLICABLE (there was nothing here to decide about, with its own
 * reason), or — expressed as a null verdict at the call site — NOTHING to say.
 *
 * Most rules only ever flag or stay silent, and return a plain message string for that.
 * This value object exists for the rules that have a real third answer: a type-change
 * classifier that meets a transition its matrix does not cover cannot honestly say
 * "safe", so it says "undetermined" with the reason — never a silent pass, which is the
 * failure this package is built against.
 *
 * ## Silence and a reasoned PASS are not the same answer
 *
 * Returning nothing means "I have nothing to say about this". A pass means "I looked, the
 * thing that would normally be wrong here is present, and here is why it cannot bite".
 * A server whose default storage engine is MyISAM while MyISAM is disabled entirely is
 * exactly that: the setting looks wrong and the risk is structurally excluded, and a
 * reader deserves to be told so rather than left to notice the absence of a finding.
 *
 * Reserved for that shape. A rule emitting a pass for every healthy subject would bury
 * the findings that matter under a report of things that are fine.
 */
final readonly class RuleVerdict
{
    private function __construct(
        public string $message,
        public ?UndeterminedReason $undeterminedReason,
        public bool $isPass = false,
        /**
         * Set exactly when the verdict is not-applicable.
         *
         * A field rather than a second boolean beside `$isPass`: two flags admit the state
         * "pass AND not-applicable", which means nothing, and the type would then need a
         * rule about itself that nothing enforces. A reason that is present or absent
         * cannot express a contradiction.
         */
        public ?NotApplicableReason $notApplicableReason = null,
        /**
         * The schema object this verdict is ABOUT, when the rule knows it.
         *
         * Null for almost every rule, and that is the honest default: a verdict about a
         * statement is located at the statement, and inventing an object for it would name
         * something the rule never identified. It is set by the rules whose finding really is
         * about one named object — an unvalidated constraint, an index left half-built — because
         * a finding that carries its object can be matched to the same object seen elsewhere:
         * in the catalog by a deploy check, in the debt ledger by a later run. Without it those
         * are two unrelated sentences about one thing.
         */
        public ?string $objectName = null,
        public ?SchemaObjectType $objectType = null,
        /**
         * The severity THIS verdict carries, when it differs from the rule's own.
         *
         * Null for almost every rule, and null means "use the rule's". A rule's severity is a
         * property of the rule, and that is right for the rules whose every finding says the same
         * thing about the same kind of defect.
         *
         * It is set where one rule honestly has two loudnesses. The privacy dictionary is the case
         * it was added for: `iban` in a column name is a strong signal and `religion` is also an
         * ordinary word in a CMS, and the artifact records which is which precisely so the finding
         * can be quieter for the weak one. Splitting that into two rule IDs would put the same
         * concern under two names in every baseline and every suppression annotation, which is a
         * cost paid by every consumer forever to work around a missing field.
         *
         * Additive in the same way `$objectName` above was: absent, nothing changes for any
         * existing rule.
         */
        public ?Severity $severity = null,
    ) {}

    /**
     * The statement is unsafe: a failing finding with this message.
     *
     * The object is optional and additive. A rule that names it gets an identity on its finding
     * that survives into every reporter and can be compared across runs; one that does not is
     * unchanged, which is why this could be added without touching a single existing rule.
     */
    public static function flag(
        string $message,
        ?string $objectName = null,
        ?SchemaObjectType $objectType = null,
        ?Severity $severity = null,
    ): self {
        return new self($message, null, objectName: $objectName, objectType: $objectType, severity: $severity);
    }

    /** The rule could not decide: an undetermined finding with this reason and message. */
    public static function undetermined(string $message, UndeterminedReason $reason): self
    {
        return new self($message, $reason);
    }

    /**
     * The rule looked and found the risk structurally excluded — a PASS with its reason stated.
     *
     * Not the same as returning nothing. Silence says "nothing to report"; this says "the thing
     * that would be wrong here is present, and here is why it cannot bite", which a reader cannot
     * infer from an absent finding.
     */
    public static function pass(string $message): self
    {
        return new self($message, null, true);
    }

    /**
     * The rule does not apply here at all — a different answer from every other one.
     *
     * Not silence: silence says "nothing to report", and a reader cannot tell that from
     * "there was nothing here to look at". Not a pass either, which claims the risk was
     * present and structurally excluded. And not undetermined, which is a question left
     * open — `--strict` escalates those, and escalating "there was no question" would put
     * a line in a pipeline that no change can remove.
     */
    public static function notApplicable(string $message, NotApplicableReason $reason): self
    {
        return new self($message, null, false, $reason);
    }

    public function isUndetermined(): bool
    {
        return $this->undeterminedReason instanceof UndeterminedReason;
    }

    public function isNotApplicable(): bool
    {
        return $this->notApplicableReason instanceof NotApplicableReason;
    }
}
