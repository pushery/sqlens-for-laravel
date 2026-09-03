<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Lint\LintOutcome;
use Pushery\SQLens\Reporting\RunContext;

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
