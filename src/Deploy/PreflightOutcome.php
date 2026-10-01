<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Lint\LintOutcome;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\Summary\AxisSummary;

/**
 * Everything one predeploy run produced — the preflight report, the lint half, and the two facts a
 * caller needs to explain the run afterwards.
 *
 * ## Why this exists rather than a report alone
 *
 * A predeploy verdict is TWO halves that travel as one result: findings about the migrations about
 * to run, and findings about the instance they will run against. A caller that received only the
 * preflight report would have to run the lint half itself — and two resolutions of "which
 * migrations are pending" are two answers, one of which drifts.
 *
 * ## Why a refusal is a value here
 *
 * A connection that cannot be resolved, or a preflight session that cannot be opened, is a
 * MISCONFIGURATION rather than a finding: nothing was learned about the database, and reporting a
 * clean run would be the silent green this whole gate exists to refuse. It is carried as a named
 * value rather than thrown, because both callers turn it into their own shape — an exit code and a
 * message for the command, a three-valued answer for the protocol.
 */
final readonly class PreflightOutcome
{
    /**
     * @param  string|null  $connection  the connection the run addressed, or null when none resolved
     * @param  string|null  $refusal  why the run could not happen at all — set exactly when `report` is null
     * @param  array<string, int|null>|null  $sessionTimeouts  the bounds the session REPORTED, never the ones it asked for
     * @param  Result|null  $result  BOTH halves as one verdict — findings about the migrations and
     *                               findings about the instance. Assembled once, in the service, because two
     *                               callers rendering it would be two chances to merge it differently, and a
     *                               consumer would then have to choose which document is "the" verdict.
     * @param  RunContext|null  $context  the header that goes with that verdict, from the same place
     */
    private function __construct(
        public ?string $connection,
        public ?string $refusal,
        public ?PreflightReport $report,
        public ?LintOutcome $lint,
        public ?CatalogSkip $advisory,
        public ?array $sessionTimeouts,
        public int $budgetMs,
        public int $budgetMsConsumed,
        public string $profile,
        public ?Result $result = null,
        public ?RunContext $context = null,
    ) {}

    /** A run that never happened, and the named reason. */
    public static function refused(string $reason, ?string $connection, string $profile): self
    {
        return new self($connection, $reason, null, null, null, null, 0, 0, $profile);
    }

    /**
     * A run that happened.
     *
     * @param  array<string, int|null>|null  $sessionTimeouts
     */
    public static function of(
        string $connection,
        PreflightReport $report,
        LintOutcome $lint,
        ?CatalogSkip $advisory,
        ?array $sessionTimeouts,
        int $budgetMs,
        int $budgetMsConsumed,
        string $profile,
        Result $result,
        RunContext $context,
    ): self {
        return new self($connection, null, $report, $lint, $advisory, $sessionTimeouts, $budgetMs, $budgetMsConsumed, $profile, $result, $context);
    }

    /**
     * Whether the deploy proceeds, over BOTH halves.
     *
     * The instance checks decided it alone for a long time, while the findings about the pending
     * migrations went into the same document marked as blocking: a critical password literal in a
     * migration stood beside `overall_status: fail` and an exit code of 0. So the migration half is
     * judged here as `sqlens:lint` judges it under the same profile, over the severities the
     * statistics raised: a finding over the gate stops the deploy, and a finding that could not be
     * determined holds it back only where the profile is strict about them. The checks keep their
     * own rule, because a check is about the instance the deploy is about to change: every failing
     * one stops it, and every unanswered one holds it back.
     *
     * A waiver opens for what could not answer and never for a problem. It has to cover every such
     * answer, from either half, or the deploy is held back.
     */
    public function verdict(UndeterminedWaiver $waiver): PreflightVerdict
    {
        if (! $this->report instanceof PreflightReport || ! $this->result instanceof Result || ! $this->context instanceof RunContext || ! $this->lint instanceof LintOutcome) {
            return PreflightVerdict::of(PreflightBlocker::Refused);
        }

        // Before every finding, as in `sqlens:lint`: a baseline nobody pruned is a broken instruction
        // file, and it must not hide behind the findings of the run that revealed it.
        if ($this->lint->staleBaselineBreaks) {
            return PreflightVerdict::of(PreflightBlocker::StaleBaseline);
        }

        if ($this->report->blocks() && ! $this->blockedOnlyByUndetermined()) {
            return PreflightVerdict::of(PreflightBlocker::CheckFailed);
        }

        // The whole result, so the severities the statistics raised are the ones judged. A failing
        // check was decided above, so a breach left here is a finding about a pending migration.
        if (AxisSummary::for($this->result, $this->context)->breached()) {
            return PreflightVerdict::of(PreflightBlocker::MigrationFinding);
        }

        $reasons = [
            ...array_map(static fn (CheckResult $result): ?UndeterminedReason => $result->undeterminedReason, $this->report->undetermined()),
            ...array_map(
                static fn (Finding $finding): ?UndeterminedReason => $finding->status->reason,
                $this->context->strictUndetermined ? $this->undeterminedMigrationFindings($this->lint) : [],
            ),
        ];

        if ($reasons === []) {
            return PreflightVerdict::of(PreflightBlocker::Nothing);
        }

        return $waiver->opensForReasons($reasons)
            ? PreflightVerdict::waivedFor($waiver->reasonsItNamesAmong($reasons))
            : PreflightVerdict::of(PreflightBlocker::Unanswered);
    }

    /**
     * What this run could not answer, from either half, one line each: an unanswered check with its
     * reason, and a finding about a pending migration that could not be determined.
     *
     * Every one of them, whether or not it holds the deploy back. A protocol answer is three-valued,
     * and a run that could not judge a migration has not said it is fine, even where the profile
     * lets the deploy proceed past it.
     *
     * A run that never happened lists nothing: no check was asked, and why the run did not happen
     * travels in `refusal`.
     *
     * @return list<string>
     */
    public function unanswered(): array
    {
        // Both halves are narrowed, as `verdict()` narrows them. `of()` sets the report and the lint
        // half together and `refused()` sets neither, so only a refusal returns here.
        if (! $this->report instanceof PreflightReport || ! $this->lint instanceof LintOutcome) {
            return [];
        }

        return [
            ...array_map(static fn (CheckResult $result): string => $result->checkId.' ('.$result->reason.')', $this->report->undetermined()),
            ...array_map(
                static fn (Finding $finding): string => $finding->ruleId.' ('.($finding->status->reason->value ?? 'undetermined').')',
                $this->undeterminedMigrationFindings($this->lint),
            ),
        ];
    }

    /**
     * The findings about a pending migration that could not be determined.
     *
     * Handed the lint half rather than reading it, because both callers have narrowed it already.
     *
     * @return list<Finding>
     */
    private function undeterminedMigrationFindings(LintOutcome $lint): array
    {
        return array_values(array_filter(
            $lint->result->findings,
            static fn (Finding $finding): bool => $finding->status->outcome === Outcome::Undetermined,
        ));
    }

    /**
     * Whether every blocking result is one that could not answer.
     *
     * The one question `--allow-undetermined` is allowed to change the answer to, and it lives here
     * rather than in either caller: the command and the protocol tool must agree about what "only
     * undetermined" means, and two readings of `$report->results` would be two chances to disagree
     * about whether a deploy proceeds.
     */
    public function blockedOnlyByUndetermined(): bool
    {
        if (! $this->report instanceof PreflightReport) {
            return false;
        }

        $blocking = array_filter(
            $this->report->results,
            static fn (CheckResult $result): bool => $result->isBlocking(),
        );

        return $blocking !== [] && count($this->report->undetermined()) === count($blocking);
    }
}
