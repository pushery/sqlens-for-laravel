<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use LogicException;
use Pushery\SQLens\Agent\Remediation\RemediationValidator;
use Pushery\SQLens\Capture\PreScan\PreScanHit;
use Pushery\SQLens\Capture\Rules\CaptureRule;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\PreScanDetector;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\MigrationSql;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Turns a finished capture run into the findings a lint run reports — the one bridge
 * from the capture model into the finding model, so "which findings did this run
 * produce" has a single answer.
 *
 * Three sources feed it, and every migration passes through all three:
 *
 *   - the level-0 capture-outcome rules (empty capture, a pretend/shadow failure, or
 *     an undetermined capture without a pre-scan hit), each judging the RESULT;
 *   - the static pre-scan hits, each turned into its own addressable `CAP.PRESCAN.*`
 *     undetermined finding located to the line it fired on — so a migration flagged
 *     for several independent reasons reports each, not just the first;
 *   - the driver's own SQL rules, run over the canonicalized statements of a
 *     successful capture (empty for now — the rule packs land later, and an empty
 *     rule set is a documented intermediate state, never read as "checked, all clean").
 *
 * "No silent green" is the whole point of running all three: a migration the capture
 * could not conclude — a pre-scan flag, an unparsable file, a rejected statement —
 * always leaves an undetermined finding behind, so it colors the run's three-valued
 * verdict and never vanishes into an empty pass.
 *
 * It reads a capture the layer already produced and evaluates rules that touch no
 * database, so the whole collection is side-effect free (primum non nocere), and it
 * knows no concrete driver — the driver's rules arrive through the contract.
 */
final readonly class CaptureFindingCollector
{
    /** @var list<CaptureRule> */
    private array $captureRules;

    /** @var array<string, CaptureRuleMetadata> */
    private array $preScanMetadata;

    /**
     * The validator every payload passes, built once.
     *
     * Not injectable, and that is the point: an injection seam here would be a way to run the
     * collector without it, and "unbypassable" is the whole property this placement buys.
     */
    private RemediationValidator $remediationValidator;

    /**
     * @param  iterable<CaptureRule>  $captureRules  the level-0 capture-outcome family
     * @param  iterable<PreScanDetector>  $detectors  the pre-scan detectors whose hits this run may carry — their metadata is the source of each CAP.PRESCAN finding's category, level, and documentation page
     */
    public function __construct(iterable $captureRules, iterable $detectors)
    {
        $this->remediationValidator = new RemediationValidator;

        $this->captureRules = is_array($captureRules) ? array_values($captureRules) : iterator_to_array($captureRules, false);

        $metadata = [];

        foreach ($detectors as $detector) {
            $entry = $detector->metadata();
            $metadata[$entry->id] = $entry;
        }

        $this->preScanMetadata = $metadata;
    }

    /**
     * Every finding the run produced, in capture order (the caller's Result::of
     * deduplicates and orders them for reporting).
     *
     * @param  iterable<Rule>  $subjectRules  the resolved driver's SQL rules
     * @return list<Finding>
     */
    public function collect(CaptureRun $run, iterable $subjectRules, SubjectContext $context, string $projectRoot): array
    {
        $subjectRules = is_array($subjectRules) ? array_values($subjectRules) : iterator_to_array($subjectRules, false);

        // The run's own statements, once, so every subject carries the same view of what the
        // WHOLE run does — the material a rule needs when its question is about an absence that
        // one migration cannot settle (see MigrationContext::$runStatements). Built here rather
        // than per result: it is a fact about the run, and computing it per migration would be
        // quadratic over exactly the runs that have most files.
        $runStatements = $run->statementDigestsBySection();

        $findings = [];

        foreach ($run->results as $result) {
            // The capture-outcome rules judge the result itself (empty, failed,
            // undetermined-without-a-hit). At most one ever applies to a result.
            foreach ($this->captureRules as $rule) {
                if ($rule->appliesTo($result, $context)) {
                    $findings[] = $rule->evaluate($result, $context, $projectRoot);
                }
            }

            // Each pre-scan hit is its own addressable finding at its own line.
            foreach ($result->preScanHits as $hit) {
                $findings[] = $this->preScanFinding($hit, $result, $context, $projectRoot);
            }

            // The driver's SQL rules see only a successful capture's canonicalized
            // statements; a failed or undetermined result has no subject to hand them.
            if ($result->isPass()) {
                foreach ($result->toSubjects($context, $runStatements[$result->section->value] ?? []) as $subject) {
                    foreach ($subjectRules as $rule) {
                        if ($rule->appliesTo($subject)) {
                            foreach ($rule->evaluate($subject) as $finding) {
                                // Both marks come from what the rule DECLARED on the
                                // contract, stamped here rather than inside the rule.
                                // For confidence that is what stops a heuristic verdict
                                // reaching a reader wearing the face of a proof because
                                // someone forgot; for the downtime class it is what
                                // makes the declaration mean anything at all — a rule
                                // can name its deploy impact and, without this, the
                                // finding a deploy script reads would never carry it.
                                $marked = $finding->withConfidence($rule->confidence());
                                $downtime = $this->downtimeClassFor($rule, $subject);

                                if ($downtime instanceof DowntimeClass) {
                                    $marked = $marked->withDowntimeClass($downtime);
                                }

                                // The fix material, from the one rule that judged this statement.
                                // Stamped here for the same reason the two marks above are: it is
                                // a capability a few rules have, and asking for it at the single
                                // place findings are assembled is what stops a rule from being
                                // able to forget to attach its own.
                                $findings[] = $this->stamped($marked, $this->remediationFor($rule, $subject));
                            }
                        }
                    }
                }
            }
        }

        return $findings;
    }

    /**
     * The downtime class to stamp: the rule's constant, or the one it derives for THIS statement.
     *
     * Most rules answer with a constant and are right to — an index built without CONCURRENTLY
     * blocks, always. A rule keyed on a data table cannot: MySQL's online-DDL matrix answers per
     * operation and per server version, so two statements one rule flags can legitimately differ,
     * and a single constant would have to be wrong about one of them.
     *
     * The derived answer REPLACES the constant rather than supplementing it, so there is exactly
     * one class per finding and never a question of which of two wins. A rule that derives null
     * leaves the finding without a class — it does not silently fall back to the constant, because
     * a rule whose data source could not classify the operation is saying something, and quietly
     * substituting a default would be exactly the silent green this package refuses.
     */
    private function downtimeClassFor(Rule $rule, MigrationSql $subject): ?DowntimeClass
    {
        return $rule instanceof DerivesDowntimeClass
            ? $rule->downtimeClassFor($subject->canonicalView())
            : $rule->downtimeClass();
    }

    /**
     * The fix material for this statement, or null for the great majority of rules that have none.
     *
     * The rule is handed the same CANONICAL view {@see DerivesDowntimeClass} receives — the
     * classified statement, never the raw grammar — so a template fills its placeholders from
     * targets and key columns the classifier already resolved rather than by re-reading SQL.
     *
     * ## One rule, one claim about the deploy
     *
     * A payload names a downtime class of its own, and the finding beside it carries the one
     * stamped above. A rule that implements BOTH this and {@see DerivesDowntimeClass} therefore has
     * two places to answer the same question, and must read its payload's class from the same
     * derivation rather than from its constant — otherwise the finding and the material attached to
     * it tell a reader two different things about the same statement. No rule does both today; the
     * obligation is written here because the day one does, this is the line it will be read against.
     */
    private function remediationFor(Rule $rule, MigrationSql $subject): ?RemediationPayload
    {
        return $rule instanceof ProvidesRemediation
            ? $rule->remediationFor($subject->canonicalView())
            : null;
    }

    /**
     * The finding, carrying its material — or carrying why it does not.
     *
     * This is the ONLY place a payload reaches a finding, which is what makes the validator
     * unbypassable rather than merely available: a reporter cannot reach around it, because a
     * reporter never sees a payload that did not come through here.
     *
     * A refusal never touches the finding itself. The rule looked at the statement and was right
     * about it; what failed is the material this package built to go with it, and downgrading a real
     * verdict over our own defect would hide a problem behind a second one.
     */
    private function stamped(Finding $finding, ?RemediationPayload $payload): Finding
    {
        if (! $payload instanceof RemediationPayload) {
            return $finding;
        }

        $refusal = $this->remediationValidator->refusalFor($payload);

        return $refusal === null
            ? $finding->withRemediation($payload)
            : $finding->withRemediationRefusal($refusal);
    }

    /**
     * One pre-scan hit as an undetermined finding: the detector's own metadata gives
     * it the category, level, stability, and documentation page a report and a
     * baseline address it by; the hit gives it the line and the reason a user reads.
     */
    private function preScanFinding(PreScanHit $hit, CaptureResult $result, SubjectContext $context, string $projectRoot): Finding
    {
        // The hit's rule id always comes from a detector this collector was built
        // with, so its metadata is always present; the throw guards that invariant.
        $metadata = $this->preScanMetadata[$hit->ruleId] ?? throw new LogicException("no pre-scan metadata for rule id {$hit->ruleId}");

        return Finding::undetermined(
            $hit->ruleId,
            $metadata->messagePrefix,
            sprintf('%s (%s). The pre-scan flagged this migration, so it was not pretend-executed; shadow mode is the truth mode that can resolve it.', $hit->reason, $hit->target),
            UndeterminedReason::PreScanFlagged,
            Location::inMigration(
                $result->file,
                $result->migrationClass,
                0,
                $result->section->direction(),
                $projectRoot,
                $hit->line,
            ),
            $metadata->category,
            $metadata->level,
            $metadata->stability,
            $metadata->documentationUrl,
            $context,
            $metadata->severity,
        );
    }
}
