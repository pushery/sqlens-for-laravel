<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Agent\Remediation\RemediationValidator;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;
use Pushery\SQLens\Deploy\DebtContext;
use Pushery\SQLens\Deploy\Escalation;
use Pushery\SQLens\Deploy\SeverityEscalator;
use Pushery\SQLens\Exceptions\InvalidFindingPromotion;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The engine's central result object: immutable, fully typed, three-valued, with
 * every piece of metadata the reporter, baseline, gate and later the agent layer
 * need.
 *
 * The generic constructor is private so no caller can forget a required field;
 * findings are built through pass()/fail()/undetermined(). "No silent green" is
 * carried through from FindingStatus — an undetermined status without a reason
 * is unconstructible.
 *
 * Rule id, message prefix and documentation URL are required — public API from
 * 1.0, so no rule can retrofit them later. Level and severity are separate
 * fields (separate accessors) so the reporter can show the two axes apart.
 *
 * A finding never quotes row contents and never carries a credential value.
 */
final readonly class Finding
{
    private function __construct(
        public string $ruleId,
        public string $messagePrefix,
        public string $message,
        public FindingStatus $status,
        public Location $location,
        public Category $category,
        public Level $level,
        public StabilityTier $stability,
        public string $documentationUrl,
        public SubjectContext $context,
        public ?Severity $severity = null,
        public ?DowntimeClass $downtimeClass = null,
        public ?StatisticsContext $statistics = null,
        public ?RemediationPayload $remediation = null,
        public Confidence $confidence = Confidence::Deterministic,
        /**
         * External tools that independently reported the same thing, e.g. `squawk@2.61.0`.
         *
         * A confirmation, never a source. The finding was produced by a SQLens rule and stays
         * that rule's finding; this only records that something else looked at the same
         * statement and agreed. It exists because the alternative to recording the agreement is
         * printing it as a second finding, and a reader given the same advice twice starts
         * skimming — which is how the finding they had not seen before gets skimmed too.
         *
         * @var list<string>
         */
        public array $confirmedBy = [],
        /**
         * What a statistic did to this finding's severity, when one did.
         *
         * Null for every finding a rule rated on its own, which is all of them outside a run that
         * read a database. Absent rather than a false flag: `escalated: false` on thousands of
         * findings would be noise, and its absence already says the rule's verdict stands.
         */
        public ?Escalation $escalation = null,
        /**
         * Why this finding carries NO remediation, when something was there to carry.
         *
         * Set only by the collector, and only when a payload was produced and then REFUSED by
         * {@see RemediationValidator} — never when a rule
         * simply had nothing to say. Those are different facts: "no template for this rule" is an
         * absence a reader can act on by writing one, and "the template this rule produced could not
         * be vouched for" is a defect in this package. Collapsing them into one silence is how the
         * second becomes invisible.
         *
         * Last in the constructor on purpose. Every `with*()` method here reconstructs positionally,
         * so a parameter inserted mid-list is eleven silent breakages — the projection's key order is
         * chosen separately, and puts this one where a reader will look for it.
         *
         * A catalog key, so the reason is readable in all seven shipped locales — and machine-
         * findable, which is what lets a consumer count them.
         */
        public ?string $remediationRefusal = null,
        /**
         * The ledger's account of this debt, when the finding IS one.
         *
         * Null for every finding that is not a debt notice, which is nearly all of them — absent
         * rather than an empty record, for the same reason {@see $escalation} is: a `debt_kind` on
         * thousands of ordinary findings would be noise, and its absence already says this is not
         * a debt.
         *
         * Attached by the two notice builders and nowhere else. A rule cannot set it, and that is
         * deliberate: a rule declares that it PRODUCES a debt ({@see ProducesDebt}), the registrar
         * decides what the ledger then holds, and a rule filling this slot itself would be a
         * second, unreconciled answer to what is owed.
         *
         * After {@see $remediationRefusal} because every `with*()` here reconstructs positionally —
         * a parameter inserted mid-list is a dozen silent breakages.
         */
        public ?DebtContext $debt = null,
    ) {}

    /**
     * One instance with some fields replaced — the single place a finding is rebuilt.
     *
     * ## Why this exists, measured rather than tidied
     *
     * Every `with*()` here used to call the constructor POSITIONALLY, listing the fields it wanted
     * to carry through. That works until a field is added at the end, and then it fails in the one
     * direction nobody looks: the new field is simply not in the older lists, so any `with*()`
     * written before it silently drops it. Measured on this class — `withDowntimeClass()`,
     * `withSeverity()`, `withConfidence()` and `confirmedBy()` all dropped `remediationRefusal`,
     * which had been the last parameter since it was added, and the two before them would have
     * dropped `escalation` the same way.
     *
     * Nothing was red. A dropped optional field is an absent key in a report, and an absent
     * optional key is exactly what a finding that never had one looks like.
     *
     * Named defaults make the omission impossible instead of merely unlikely: a field added to the
     * constructor and to this signature is carried by every `with*()` at once, and one forgotten
     * here is a compile-time argument error rather than a quiet loss.
     *
     * @param  list<string>|null  $confirmedBy
     */
    private function copy(
        ?FindingStatus $status = null,
        ?string $message = null,
        ?Severity $severity = null,
        ?DowntimeClass $downtimeClass = null,
        ?StatisticsContext $statistics = null,
        ?RemediationPayload $remediation = null,
        ?Confidence $confidence = null,
        ?array $confirmedBy = null,
        ?Escalation $escalation = null,
        ?string $remediationRefusal = null,
        ?DebtContext $debt = null,
        bool $clearRemediation = false,
    ): self {
        return new self(
            $this->ruleId,
            $this->messagePrefix,
            $message ?? $this->message,
            $status ?? $this->status,
            $this->location,
            $this->category,
            $this->level,
            $this->stability,
            $this->documentationUrl,
            $this->context,
            $severity ?? $this->severity,
            $downtimeClass ?? $this->downtimeClass,
            $statistics ?? $this->statistics,
            // The one field a caller may want to REMOVE rather than replace, so it needs a flag of
            // its own: a refusal and a payload are mutually exclusive, and `null` here means "leave
            // it alone" for every other field.
            $clearRemediation ? null : ($remediation ?? $this->remediation),
            $confidence ?? $this->confidence,
            $confirmedBy ?? $this->confirmedBy,
            $escalation ?? $this->escalation,
            $remediationRefusal ?? $this->remediationRefusal,
            $debt ?? $this->debt,
        );
    }

    /**
     * The same finding, noting that an external tool reported it too.
     *
     * Additive and sorted, so the same run produces the same bytes: a set that recorded
     * agreement in arrival order would make two identical runs differ in their reports.
     */
    public function confirmedBy(string $tool): self
    {
        $confirmations = $this->confirmedBy;
        $confirmations[] = $tool;
        $confirmations = array_values(array_unique($confirmations));
        sort($confirmations);

        return $this->copy(confirmedBy: $confirmations);
    }

    /**
     * The same finding, marked with the confidence of the rule that produced it.
     *
     * The rule declares its confidence once, on the contract; the collector stamps it
     * onto every finding that rule emits. Doing it there rather than inside each rule
     * is what makes the marking impossible to forget — a heuristic rule that neglected
     * to mark its own findings would present a guess with the same face as a proof.
     */
    public function withConfidence(Confidence $confidence): self
    {
        return $this->copy(confidence: $confidence);
    }

    /**
     * The same finding, DECIDED — the one place an outcome changes after a finding is built.
     *
     * ## What it is for
     *
     * Some checks answer honestly with `undetermined` because the reading they own cannot settle the
     * question. `DEPLOY.LEGACY.ORPHAN_TRANSITION_OBJECT` is the case this was written for: a name
     * that looks like an abandoned rename is exactly what a table somebody queries every quarter
     * also looks like, and the catalog holds nothing that separates them. A SECOND, independent
     * reading can — the object appearing in no migration state at all — and when the two agree from
     * different directions, the answer is no longer a guess.
     *
     * ## Why it is narrow, and stays narrow
     *
     * It moves in exactly one direction, undetermined to fail, and refuses everything else. That is
     * not caution for its own sake: a general "set the outcome" would let a later pass overwrite an
     * earlier failure, and a report whose verdicts can be rewritten by whatever ran last is worth
     * nothing. Promotion needs agreement; it is never a way to change one's mind.
     *
     * The message is REPLACED rather than appended to by the caller, because the finding must read
     * as one statement. An undetermined message ends by saying what would settle the question — a
     * reader who then sees `fail` beside a sentence still describing uncertainty learns to distrust
     * both halves.
     *
     * The severity, location, downtime class, category and everything else carry through untouched:
     * what changed is that the question was answered, not what the object is.
     *
     * @throws InvalidFindingPromotion when the finding is not undetermined
     */
    public function settledBySecondReading(string $message): self
    {
        if ($this->status->outcome !== Outcome::Undetermined) {
            throw InvalidFindingPromotion::notUndetermined($this->ruleId, $this->status->outcome);
        }

        return $this->copy(status: FindingStatus::fail(), message: $message);
    }

    public static function pass(
        string $ruleId,
        string $messagePrefix,
        string $message,
        Location $location,
        Category $category,
        Level $level,
        StabilityTier $stability,
        string $documentationUrl,
        SubjectContext $context,
        ?Severity $severity = null,
    ): self {
        return new self(
            $ruleId, $messagePrefix, $message, FindingStatus::pass(),
            $location, $category, $level, $stability, $documentationUrl, $context, $severity,
        );
    }

    /**
     * A check that does not apply to this instance at all — never a quiet absence.
     *
     * The reason a rule needs this factory rather than returning nothing: silence and
     * not-applicable are indistinguishable in a report, and a reader takes silence for
     * "checked and fine". Saying "this engine has no such concept" costs one line and
     * removes an inference nobody should be asked to make.
     */
    public static function notApplicable(
        string $ruleId,
        string $messagePrefix,
        string $message,
        NotApplicableReason $reason,
        Location $location,
        Category $category,
        Level $level,
        StabilityTier $stability,
        string $documentationUrl,
        SubjectContext $context,
        ?Severity $severity = null,
    ): self {
        return new self(
            $ruleId, $messagePrefix, $message, FindingStatus::notApplicable($reason),
            $location, $category, $level, $stability, $documentationUrl, $context, $severity,
        );
    }

    public static function fail(
        string $ruleId,
        string $messagePrefix,
        string $message,
        Location $location,
        Category $category,
        Level $level,
        StabilityTier $stability,
        string $documentationUrl,
        SubjectContext $context,
        ?Severity $severity = null,
    ): self {
        return new self(
            $ruleId, $messagePrefix, $message, FindingStatus::fail(),
            $location, $category, $level, $stability, $documentationUrl, $context, $severity,
        );
    }

    public static function undetermined(
        string $ruleId,
        string $messagePrefix,
        string $message,
        UndeterminedReason $reason,
        Location $location,
        Category $category,
        Level $level,
        StabilityTier $stability,
        string $documentationUrl,
        SubjectContext $context,
        ?Severity $severity = null,
    ): self {
        return new self(
            $ruleId, $messagePrefix, $message, FindingStatus::undetermined($reason),
            $location, $category, $level, $stability, $documentationUrl, $context, $severity,
        );
    }

    /** A new instance carrying the downtime class; the original is untouched. */
    public function withDowntimeClass(DowntimeClass $downtimeClass): self
    {
        return $this->copy(downtimeClass: $downtimeClass);
    }

    /**
     * The maintenance-window advice this finding carries, or null when its class needs none.
     *
     * DERIVED from the downtime class rather than stored beside it. That is the whole guarantee:
     * a stored field could be set to something the class contradicts — a `rewrite` finding
     * advising an off-peak run — and nothing would notice, because the two would be independent
     * values. Derived, the advice cannot disagree with the class it restates.
     */
    public function maintenanceWindow(): ?MaintenanceWindow
    {
        return MaintenanceWindow::forDowntimeClass($this->downtimeClass);
    }

    /**
     * A new instance at a RAISED severity; the original is untouched.
     *
     * Raising only, and the guard lives at the caller rather than here — this method is the
     * mechanism, and a value object that silently refused an assignment would be harder to reason
     * about than one that does what it is told. What must never happen is a LOWER severity reaching
     * it, and {@see SeverityEscalator} is the one caller, with the rank
     * comparison that makes it impossible.
     */
    public function withSeverity(Severity $severity): self
    {
        return $this->copy(severity: $severity);
    }

    /**
     * A new instance recording that a statistic raised this finding's severity.
     *
     * Set by {@see SeverityEscalator} together with the raise itself — never on its own. The two
     * are one fact, and a finding carrying the record without the raised value (or the reverse)
     * would be a report disagreeing with itself.
     */
    public function withEscalation(Escalation $escalation): self
    {
        return $this->copy(escalation: $escalation);
    }

    /** A new instance carrying the statistics context; the original is untouched. */
    public function withStatistics(StatisticsContext $statistics): self
    {
        return $this->copy(statistics: $statistics);
    }

    /**
     * A new instance carrying the preview remediation payload; the original is
     * untouched. The core never generates a payload itself — a later layer attaches it.
     */
    public function withRemediation(RemediationPayload $remediation): self
    {
        return $this->copy(remediation: $remediation);
    }

    /**
     * The same finding, carrying the REASON its material was refused instead of the material.
     *
     * Deliberately not a second argument on {@see withRemediation()}: the two are mutually
     * exclusive, and a method that took both would let a caller ship a payload AND the note saying
     * it could not be shipped. Two methods make that unrepresentable.
     */
    public function withRemediationRefusal(string $reason): self
    {
        return $this->copy(remediationRefusal: $reason, clearRemediation: true);
    }

    /**
     * The same finding, carrying what the ledger holds about the debt it reports.
     *
     * Attached at the two places that build a debt notice, never inside a rule — the same
     * discipline as {@see self::withStatistics()}, and for the same reason: a slot each producer
     * had to remember to fill is a slot that is eventually left empty, and an empty one here reads
     * as "not a debt".
     */
    public function withDebt(DebtContext $debt): self
    {
        return $this->copy(debt: $debt);
    }

    /**
     * A deterministic array projection with a fixed key order and stable
     * snake_case keys — the shared substrate JSON, GitHub annotations, SARIF and
     * the baseline all draw from. Absent optional fields (undetermined_reason,
     * severity, downtime_class) are omitted rather than serialized as null.
     *
     * The `message` key sits directly after `message_prefix` and never carries a
     * credential value or a row's contents. Level and severity are separate keys
     * so the reporter can show the two axes apart. Rule id, message prefix and
     * documentation URL are public API from 1.0.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $projection = [
            'rule_id' => $this->ruleId,
            'message_prefix' => $this->messagePrefix,
            'message' => $this->message,
            'status' => $this->status->outcome->value,
            'undetermined_reason' => $this->status->reason?->value,
            'category' => $this->category->value,
            'level' => $this->level->value,
            'severity' => $this->severity?->value,
            'downtime_class' => $this->downtimeClass?->value,
            // Additive and optional: absent for an `online` finding, and omitted rather than
            // serialized as null by the filter below. It never weakens the downtime_class
            // contract because it is derived FROM it.
            'maintenance_window' => $this->maintenanceWindow()?->advice(),
            'confidence' => $this->confidence->value,
            'stability' => $this->stability->value,
            'documentation_url' => $this->documentationUrl,
            'location' => $this->location->toArray(),
            'context' => $this->context->toArray(),
            // Additive and optional, and it sits BEFORE the slot it explains: a reader who finds
            // no `remediation` looks up, not down. Present only when a payload existed and was
            // refused — never for a rule that produced none.
            'remediation_refusal' => $this->remediationRefusal,
            'remediation' => $this->remediation?->toArray(),
            // Additive and optional, and it never reaches a rule — this is CONTEXT on a finding
            // that already exists. Absent for a run that read no statistics, which is what `lint`
            // without a database always is, so a consumer must not read its absence as "small".
            'statistics' => $this->statistics?->toArray(),
            // Additive and optional. Omitted when nothing confirmed it, rather than shipped as an
            // empty array — a reader seeing `confirmed_by: []` would reasonably wonder which tool
            // was asked and declined, and nothing was.
            'confirmed_by' => $this->confirmedBy === [] ? null : $this->confirmedBy,
        ];

        // Spread, like the escalation below and for the same reason: `debt_state` belongs beside
        // `status`, not one level down from it. Absent entirely when the finding is not a debt —
        // which, unlike an empty record, cannot be mistaken for a debt with nothing owed.
        $projection = [...$projection, ...($this->debt?->toArray() ?? [])];

        // Spread rather than nested, so a consumer reads `escalated` / `base_severity` at the same
        // depth as `severity` — the three belong to one question and a reader comparing them should
        // not have to descend for two of them. Absent entirely when nothing escalated.
        $projection = [...$projection, ...($this->escalation?->toArray() ?? [])];

        return array_filter($projection, static fn (mixed $value): bool => $value !== null);
    }
}
