<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Attributes\SqlensIgnore;
use Pushery\SQLens\Audit\IgnoreList;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Reporting\Baseline\BaselineEntry;
use Pushery\SQLens\Reporting\Baseline\BaselineFile;
use Pushery\SQLens\Reporting\Baseline\FindingFingerprint;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\MigrationSql;

/**
 * Joins the five suppression layers into one traceable chain.
 *
 * The order is FIXED IN CODE — see {@see self::ORDER}, which is the one place it is
 * written down — and never derived from how the sources were registered or injected.
 * A precedence that depended on registration order would be a determinism break: the
 * same project, wired slightly differently, would report a different reason for the
 * same hidden finding. The first layer that covers a finding wins, and its source is
 * recorded.
 *
 * The three general layers run from the STANDING decision to the temporary one: a
 * config ignore and an audit ignore say "this rule does not apply here" and are meant
 * to stay, while a baseline records debt somebody intends to burn down and is meant
 * to shrink. Attributing a standing decision to the baseline would put it on a list
 * it never leaves, and the burn-down total would stop falling for a reason nobody can
 * find by reading the list. The destructive opt-in is last because it is not a general
 * suppression but a domain-specific CONSENT — it covers only the destructive rule
 * family, and only when the general layers left the finding standing.
 *
 * An annotation sits between them: it is a note a person wrote on one migration, so it
 * is narrower than a project-wide rule and more deliberate than a bulk acceptance.
 *
 * An `undetermined` is NOT suppressible. A check that could not run is not a
 * finding anyone accepted, so hiding it would hide the fact that it never ran.
 * The single exception is explicit and per reason: `sqlens.suppression.allow_undetermined`
 * lists the reasons a project has decided it can live with, and every suppression
 * granted that way is marked as such wherever it is shown — hiding a check that
 * could not RUN is a stronger statement than hiding a finding, and never looks
 * like an ordinary suppression.
 */
final readonly class SuppressionResolver
{
    /**
     * The fixed resolution order: standing decisions first, temporary debt next, domain consent last.
     *
     * The baseline deliberately loses every tie. It records findings somebody INTENDS to fix, and
     * the number of them is meant to fall; a config or audit ignore records that a rule never
     * applies here, and that number is meant to stay. Attributing a standing decision to the
     * baseline puts it on a burn-down list it will never leave, so the total stops falling for a
     * reason nobody can find in the list itself.
     *
     * A baseline entry SHADOWED this way is still recorded as matched, so it is not then reported
     * as stale — telling somebody to delete a line that legitimately covers a finding is worse
     * advice than saying nothing at all.
     */
    public const array ORDER = [
        ConfigSuppressionSource::SOURCE,
        AuditIgnoreSuppressionSource::SOURCE,
        BaselineSuppressionSource::SOURCE,
        AnnotationSuppressionSource::SOURCE,
        DestructiveOptInSuppressionSource::SOURCE,
        // Last, and it is the only layer that hides a finding for a reason having nothing to do
        // with a decision somebody made: the fact is already reported by one of our own rules. It
        // sits at the end because every human decision above it deserves to be the recorded reason
        // when both apply — "the project accepted this" says more than "we say it elsewhere too".
        RlsDedupeSuppressionSource::SOURCE,
        // The second de-duplication layer, and its position relative to the first is immaterial by
        // construction rather than by luck: the RLS layer only ever hides a FOREIGN id and this one
        // only ever hides one of OURS, so no finding can be covered by both. The order is still
        // written down, because a precedence nobody wrote down is one the next reader has to guess.
        PairedViewDedupeSuppressionSource::SOURCE,
    ];

    /** @param  list<UndeterminedReason>  $allowUndetermined */
    public function __construct(
        private BaselineSuppressionSource $baseline,
        private ConfigSuppressionSource $config,
        private AuditIgnoreSuppressionSource $auditIgnore,
        private AnnotationSuppressionSource $annotation,
        private DestructiveOptInSuppressionSource $destructiveOptIn,
        private array $allowUndetermined = [],
        private ?RlsDedupeSuppressionSource $rlsDedupe = null,
        // Not nullable, unlike the layer above it. That one waits for an external adapter nobody has
        // wired, so loading its table on every run would be cost with no reader; this one has both
        // halves of both its pairs in the tree today and fires on any production run that reads a
        // logging setting. A default instance keeps every existing caller — including the two
        // runners — on the behavior the table describes, instead of leaving the mechanism switched
        // off in exactly the paths it was built for.
        private PairedViewDedupeSuppressionSource $pairedViewDedupe = new PairedViewDedupeSuppressionSource,
        // Defaulted like its sibling above rather than injected: it reads no file and holds no
        // state, so a resolver built anywhere gets the layer without having to know it exists.
        private CrossSourceDedupeSuppressionSource $crossSourceDedupe = new CrossSourceDedupeSuppressionSource,
    ) {}

    /** @param  list<UndeterminedReason>  $allowUndetermined */
    public static function for(
        BaselineFile $baseline,
        mixed $ignore,
        array $allowUndetermined = [],
        bool $allowDestructive = false,
        ?IgnoreList $auditIgnore = null,
    ): self {
        return new self(
            new BaselineSuppressionSource($baseline),
            ConfigSuppressionSource::fromConfig($ignore),
            // Empty for a lint run, which addresses no database objects and has nothing this list
            // could name. Passing an empty one rather than making the source optional keeps the
            // resolution ORDER a fixed list of five rather than a shape that varies by suite.
            new AuditIgnoreSuppressionSource($auditIgnore ?? IgnoreList::empty()),
            new AnnotationSuppressionSource,
            new DestructiveOptInSuppressionSource($allowDestructive),
            $allowUndetermined,
        );
    }

    /**
     * @param  list<SuppressionCandidate>  $candidates
     * @param  list<string>  $unverifiablePrefixes  rule-id prefixes whose SOURCE did not answer
     *                                              this run, so a baseline entry naming one was
     *                                              not checked rather than fixed
     */
    public function resolve(array $candidates, Suite $suite, array $unverifiablePrefixes = []): SuppressionOutcome
    {
        $visible = [];
        $suppressed = [];
        $matchedBaselineKeys = [];
        $usedIgnoreIndices = [];

        // Computed once, from the candidate list that is already complete, and needed by exactly one
        // layer: the paired-view dedupe, which may only hide a privacy view when its hardening
        // partner genuinely reported something in THIS run.
        $reportedIds = $this->reportedIds($candidates);

        // Beside it, and for the same reason: entitlement to hide a migration finding depends on
        // what the CATALOG half reported in this run, which cannot be answered one finding at a time.
        $catalogIdentities = CrossSourceDedupeSuppressionSource::catalogIdentities(
            array_map(static fn (SuppressionCandidate $candidate): Finding => $candidate->finding, $candidates),
        );

        foreach ($candidates as $candidate) {
            $suppression = $this->firstCovering($candidate, $suite, $matchedBaselineKeys, $usedIgnoreIndices, $reportedIds, $catalogIdentities);

            if ($suppression instanceof Suppression) {
                $suppressed[] = new SuppressedFinding($candidate->finding, $suppression);

                continue;
            }

            $visible[] = $candidate->finding;
        }

        [$visible, $suppressed] = $this->restoreOrphanedViews($visible, $suppressed);

        return new SuppressionOutcome(
            visible: $visible,
            suppressed: $suppressed,
            staleBaselineEntries: $this->baseline->staleEntries($matchedBaselineKeys, $unverifiablePrefixes),
            unusedIgnoreRules: $this->config->unusedRules($usedIgnoreIndices),
            unverifiableBaselineEntries: $this->baseline->unverifiableEntries($matchedBaselineKeys, $unverifiablePrefixes),
        );
    }

    /**
     * The rule ids that REPORTED something in this run.
     *
     * A pass is deliberately not "reported": a rule that looked and found nothing wrong has produced
     * no problem for a second view to be part of. Counting it would let a silent hardening view hide
     * a real privacy one — the exact inversion this layer exists to prevent.
     *
     * @param  list<SuppressionCandidate>  $candidates
     * @return list<string>
     */
    private function reportedIds(array $candidates): array
    {
        $ids = [];

        foreach ($candidates as $candidate) {
            if ($candidate->finding->status->outcome !== Outcome::Pass) {
                $ids[$candidate->finding->ruleId] = true;
            }
        }

        return array_keys($ids);
    }

    /**
     * Hand back any privacy view whose hardening partner did not survive the other layers.
     *
     * The single-pass loop cannot decide this. Whether the partner is VISIBLE is only known once
     * every candidate has been resolved, and a partner hidden by a config ignore, a baseline entry
     * or an annotation would otherwise take the privacy view down with it — two findings gone, one
     * server value nobody looks at, and a report that reads exactly like a clean one.
     *
     * Only suppressions this layer created are reconsidered. A privacy view the PROJECT chose to
     * suppress stays suppressed: that is somebody's decision, and this pass is not entitled to
     * overturn it.
     *
     * @param  list<Finding>  $visible
     * @param  list<SuppressedFinding>  $suppressed
     * @return array{list<Finding>, list<SuppressedFinding>}
     */
    private function restoreOrphanedViews(array $visible, array $suppressed): array
    {
        $visibleIds = [];

        foreach ($visible as $finding) {
            $visibleIds[$finding->ruleId] = true;
        }

        $kept = [];

        foreach ($suppressed as $entry) {
            $partner = $entry->suppression->source === PairedViewDedupeSuppressionSource::SOURCE
                ? $this->pairedViewDedupe->supersedingIdFor($entry->finding->ruleId)
                : null;

            if ($partner !== null && ! isset($visibleIds[$partner])) {
                $visible[] = $entry->finding;

                continue;
            }

            $kept[] = $entry;
        }

        return [$visible, $kept];
    }

    /**
     * @param  list<string>  $matchedBaselineKeys
     * @param  list<int>  $usedIgnoreIndices
     * @param  list<string>  $reportedIds
     * @param  list<string>  $catalogIdentities
     */
    private function firstCovering(
        SuppressionCandidate $candidate,
        Suite $suite,
        array &$matchedBaselineKeys,
        array &$usedIgnoreIndices,
        array $reportedIds,
        array $catalogIdentities,
    ): ?Suppression {
        $undetermined = $candidate->finding->status->outcome === Outcome::Undetermined;

        if ($undetermined && ! $this->undeterminedIsAllowed($candidate)) {
            return null;
        }

        // The baseline is asked FIRST and answers LAST. It has to be asked here, before anything
        // else can win, because a config ignore that shadows a baseline entry must not make that
        // entry look stale — a report telling somebody to delete a line that is legitimately
        // covering a finding is worse advice than saying nothing. So a shadowed entry is recorded
        // as matched and its suppression is then discarded in favor of the standing decision.
        $entry = $candidate->fingerprint instanceof FindingFingerprint
            ? $this->baseline->suppressionFor($candidate->finding, $candidate->fingerprint, $candidate->ordinal, $undetermined)
            : null;

        if ($entry instanceof BaselineEntry) {
            $matchedBaselineKeys[] = $entry->key();
        }

        $ignore = $this->config->suppressionFor($candidate->finding, $suite, $undetermined);

        if ($ignore instanceof ConfigIgnoreRule) {
            $usedIgnoreIndices[] = $ignore->index;

            return new Suppression(
                source: ConfigSuppressionSource::SOURCE,
                reason: $ignore->reason,
                undeterminedAllowed: $undetermined,
            );
        }

        // After the baseline and the shared config ignore, before the per-migration annotation: it
        // is a project-wide instruction like those two, and narrower than neither.
        $auditIgnore = $this->auditIgnore->suppressionFor($candidate->finding);

        if ($auditIgnore instanceof Suppression) {
            return $undetermined
                ? new Suppression($auditIgnore->source, $auditIgnore->reason, undeterminedAllowed: true)
                : $auditIgnore;
        }

        // …and only now the baseline, which loses every tie it is in. A baseline entry is TEMPORARY
        // debt somebody intends to burn down; a config ignore or an audit ignore is a standing
        // decision that this never applies here. Counting a standing decision as debt puts it on a
        // burn-down list it will never leave, and the burn-down number then never reaches zero for
        // reasons nobody can find.
        if ($entry instanceof BaselineEntry) {
            return new Suppression(
                source: BaselineSuppressionSource::SOURCE,
                reason: 'recorded in the baseline as accepted',
                undeterminedAllowed: $undetermined,
            );
        }

        if ($candidate->subject instanceof MigrationSql) {
            $annotation = $this->annotation->suppressionFor($candidate->subject, $candidate->finding->ruleId);

            if ($annotation instanceof SqlensIgnore) {
                return new Suppression(
                    source: AnnotationSuppressionSource::SOURCE,
                    reason: $annotation->reason,
                    until: $annotation->until,
                    undeterminedAllowed: $undetermined,
                );
            }
        }

        // Last: the destructive-family consent — the per-migration attribute or the
        // project-wide switch. It builds its own Suppression (the reason has two shapes)
        // and covers only the destructive rule ids, so it never hides anything else.
        $consent = $this->destructiveOptIn->consentFor($candidate->finding, $candidate->subject);

        if ($consent instanceof Suppression) {
            return $consent;
        }

        // The de-duplication layer, and the only one that can be absent: no external adapter is
        // wired yet, so a resolver built without it behaves exactly as it did before this existed.
        // Nullable rather than always-on for that reason — a layer that loaded a file on every run
        // to hide nothing would be cost with no reader.
        $foreign = $this->rlsDedupe?->supersessionFor($candidate->finding);

        if ($foreign instanceof Suppression) {
            return $foreign;
        }

        // …and the pair of our own views on one server setting. It gets the ids that reported this
        // run because presence, not the table, is what entitles it to hide anything — and even the
        // suppression it returns here is PROVISIONAL: `restoreOrphanedViews()` takes it back if the
        // partner turns out to have been hidden by one of the layers above.
        $paired = $this->pairedViewDedupe->supersessionFor($candidate->finding, $reportedIds);

        if ($paired instanceof Suppression) {
            return $paired;
        }

        // Last of the de-duplication layers, and last on purpose: it is the only one that needs an
        // OBJECT to agree and not just a rule id, so it is the narrowest claim of the three. A
        // narrower layer running earlier would attribute a hiding to the specific reason when a
        // broader one was equally true, and the reason is what a reader acts on.
        return $this->crossSourceDedupe->supersessionFor($candidate->finding, $catalogIdentities);
    }

    /** Whether the project has explicitly accepted living without THIS check. */
    private function undeterminedIsAllowed(SuppressionCandidate $candidate): bool
    {
        $reason = $candidate->finding->status->reason;

        return $reason instanceof UndeterminedReason && in_array($reason, $this->allowUndetermined, true);
    }
}
