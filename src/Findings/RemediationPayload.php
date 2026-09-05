<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\Rules\StabilityTier;

/**
 * The reserved slot for a machine-readable fix template on a finding — typed,
 * versioned and marked `preview`, so a later layer can fill in the full schema
 * without breaking the Finding VO and without a stray minor accidentally
 * promising a stable API.
 *
 * The stability policy: the payload is `preview` for the whole 1.x line and only
 * promotes to stable at a
 * major, evidence-bound. The stability marker has ONE source of truth, a constant
 * `preview` — no code path marks a payload stable until that promotion, which is a
 * deliberate future change. It rides under its own `remediation` key, carrying its
 * `schema_version` and `stability` inline so a consumer sees the maturity without
 * an external lookup, and is omitted from serialization while empty (no null
 * noise).
 *
 * This is a passive container: the core never generates a payload and never
 * applies one. There is no auto-fix — the payload is structured material
 * for an agent, which the tool re-verifies afterwards.
 */
final readonly class RemediationPayload
{
    /**
     * Monotonic; bumps on any change to the field set, even in preview. Versions
     * the envelope, not the package SemVer.
     */
    public const int SCHEMA_VERSION = 2;

    /**
     * Where the published contract lives, relative to the package root — in exactly ONE place.
     *
     * A path written twice is a path that disagrees with itself the day somebody moves the file,
     * and the half that still points at the old place fails in whichever direction nobody is
     * watching. Named here rather than in the test that reads it, so a move stays a one-line change.
     */
    public const string PUBLISHED_SCHEMA = 'resources/data/schemas/remediation-payload-v2.schema.json';

    // 2 since the `subject` field landed, and the version this replaced said 1 for a reason that had
    // QUIETLY EXPIRED — which is why the old text is not left standing to be believed.
    //
    // It read: "no payload of any shape has ever been RELEASED, so no consumer has a version 1 to
    // migrate away from", and it closed with "the bump obligation is live from the first tagged
    // release onward". Both halves were true when written. By the time `subject` was added, three
    // tags had shipped — v0.1.2, v0.2.0, v0.3.0 — each carrying this class, seventeen rules that
    // construct it, and the v1 schema document itself under `resources/`, which is on the release
    // allowlist. The obligation the comment set for itself had come due, and the comment was the
    // only place that knew.
    //
    // `subject` was argued through as additive, and the argument was nearly right: a reader that
    // ignores the key does read what it read before. A VALIDATOR does not. The v1 document carries
    // `additionalProperties: false`, so the copy a consumer vendored from v0.3.0 rejects every
    // payload this package now produces — and `subject` also went into `required`, so the v1
    // document in THIS tree rejects every payload v0.3.0 produced. Both directions break while both
    // payloads claim to be version 1, which is the one thing a version field exists to prevent.
    //
    // So version 1 is frozen at the bytes v0.3.0 published and kept in the tree beside this one.
    // `PublishedSchemaTest` holds every published version's contract-bearing content by digest, so
    // the next change to the field set cannot be argued through again — it goes red until a new
    // file and a new number exist. Descriptions are normalized out of that digest: fixing a
    // sentence is not a contract change and must not cost a version.

    /**
     * The single source of truth for the payload's maturity — constant `preview`
     * until an evidence-bound major promotion. Kept separate from a rule's own
     * stability tier: a stable rule may carry a preview payload.
     */
    public const StabilityTier STABILITY = StabilityTier::Preview;

    /** @var list<RemediationStep> the safe sequence, sorted by `order` */
    public array $steps;

    /**
     * The constructor's documentation, at the constructor. It used to sit one declaration higher,
     * where PHP attached it to `$steps` while the constructor itself kept a stub of bare types —
     * two blocks describing one thing, and the reader was shown the wrong one.
     *
     * @param  list<RemediationStep>  $steps  the safe sequence; sorted by `order` on construction,
     *                                        so a consumer never has to and two payloads built from
     *                                        the same steps in different orders serialize alike
     * @param  string|null  $ruleId  which rule this fixes — carried so a payload lifted out of a
     *                               finding still says what it is about
     * @param  list<string>  $preconditions  translation keys for what must be true BEFORE step one;
     *                                       a sequence whose preconditions nobody checked is a
     *                                       sequence that fails halfway
     * @param  string|null  $verification  translation key for how to confirm it worked — the step
     *                                     an agent skips, and the reason this package re-verifies
     * @param  list<string>  $references  documentation URLs; addresses, never prose
     */
    public function __construct(
        array $steps,
        public RemediationStrategy $strategy = RemediationStrategy::None,
        public ?string $ruleId = null,
        public ?DowntimeClass $downtimeClass = null,
        public array $preconditions = [],
        public ?string $verification = null,
        public array $references = [],
        /**
         * The debt this sequence leaves open between its steps, in the LEDGER's own vocabulary —
         * or null, which is the answer for almost every sequence.
         *
         * Some safe patterns are safe precisely because they stop halfway on purpose: a constraint
         * added `NOT VALID` is correct and incomplete at the same moment, and stays that way until
         * a later migration validates it. That gap is not a flaw in the advice, it is the shape of
         * the advice — and a payload that named the first half without naming the account it opens
         * would be handing somebody a silent, permanent debt while calling it a fix.
         *
         * The word is the registrar's, never this package's second spelling of it. The migration
         * side and the catalog side already have to agree on it, and a third spelling here would be
         * a debt nobody could join to the entry it describes.
         */
        public ?string $debtKind = null,
        /**
         * What this template is ABOUT — a statement the reader wrote, or an object the run found.
         *
         * Defaulted, and the default is what keeps this a within-version addition: every payload
         * that existed before this field rewrote a statement, so `statement` restates what was
         * already true rather than deciding anything new. {@see RemediationSubject} carries why a
         * discriminator was chosen over a second payload type, and why the schema version stays 1.
         *
         * It is not decoration. Several fields mean something different for the two subjects and
         * one means nothing at all, so the validator refuses a payload that sets one where it does
         * not apply — absent is a fact, present-and-ignored is a lie a reader cannot see.
         */
        public RemediationSubject $subject = RemediationSubject::Statement,
    ) {
        // Sorted here rather than trusted from the caller. `order` is the safety property of the
        // whole payload — a sequence applied out of order is not a slower fix, it is a different
        // and usually broken one — and sorting once at the boundary means no reader has to know.
        usort($steps, static fn (RemediationStep $a, RemediationStep $b): int => $a->order <=> $b->order);

        $this->steps = $steps;
    }

    /**
     * A deterministic array projection under the payload's own key, carrying the
     * schema version and the visible preview marker inline. An absent SQL template
     * is omitted rather than serialized as null.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $projection = [
            'schema_version' => self::SCHEMA_VERSION,
            'stability' => self::STABILITY->value,
            'rule_id' => $this->ruleId,
            // Emitted ALWAYS, including for the default. A discriminator that appeared only on the
            // unusual case would leave a consumer inferring the common one from its absence, which
            // is the guessing this field exists to end.
            'subject' => $this->subject->value,
            'strategy' => $this->strategy->value,
            'downtime_class' => $this->downtimeClass?->value,
            'debt_kind' => $this->debtKind,
            'preconditions' => $this->preconditions === [] ? null : $this->preconditions,
            'steps' => array_map(static fn (RemediationStep $step): array => $step->toArray(), $this->steps),
            'verification' => $this->verification,
            'references' => $this->references === [] ? null : $this->references,
        ];

        return array_filter($projection, static fn (mixed $value): bool => $value !== null);
    }
}
