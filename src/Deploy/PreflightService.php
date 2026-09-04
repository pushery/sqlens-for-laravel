<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\PreflightConnection;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\ReadsSessionBounds;
use Pushery\SQLens\Contracts\SessionDefenses;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\RunMetadata;
use Pushery\SQLens\Lint\LintRuns;
use Pushery\SQLens\Reporting\ConfigRunContextCollector;
use Pushery\SQLens\Reporting\CredentialRedaction;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * The predeploy composition, moved out of the command that used to hold it.
 *
 * Nothing here is new. Every step, every comment and every ordering decision came from
 * `PredeployCommand::handle()` unchanged — what changed is only that a second caller may depend on
 * the shape instead of on the command. See {@see PreflightRuns} for why that mattered enough to
 * move.
 */
final readonly class PreflightService implements PreflightRuns
{
    /**
     * The configuration keys this service composes, as constants rather than inline strings.
     *
     * The key reaching `Repository::get()` is built (`'sqlens.preflight.'.$key`), so a typo in it is
     * invisible to every static check AND to the config validator: an unknown key would be refused,
     * but a MISREAD one simply never matches and falls through to the shipped default. The gate would
     * keep working, quietly ignoring what the project configured.
     *
     * Named here so the test that reconciles them against `config/sqlens.php` and `ConfigSchema` has
     * something to reconcile, instead of parsing a concatenation out of this file.
     */
    public const string LONG_RUNNING_KEY = 'long_running_ms';

    public const string REPLICATION_LAG_KEY = 'replication_lag_ms';

    public function __construct(
        private Repository $config,
        private ReaderConnectionFactory $connections,
        private PreflightRunner $runner,
        private LintRuns $lint,
        private SessionDefenses $defenses,
        private CatalogReaderFactory $readers,
        private ReadsSessionBounds $sessionBounds,
        private ConfigRunContextCollector $runContext,
        private FindingEscalation $escalation,
    ) {}

    public function run(?string $connection = null, ?string $profile = null, ?int $budgetMs = null): PreflightOutcome
    {
        $resolution = PreflightConnection::resolve($this->config);
        $name = $connection !== null && $connection !== '' ? $connection : $resolution->name;
        $profileName = $profile !== null && $profile !== '' ? $profile : 'predeploy';

        if ($name === null) {
            // Misconfiguration rather than a finding: nothing was learned about the database, and
            // reporting a clean run here would be the silent green this whole gate exists to refuse.
            return PreflightOutcome::refused((string) $resolution->skip?->detail, null, $profileName);
        }

        $preflight = $this->connections->forPreflight(
            $this->defenses,
            $this->readers,
            new SubjectContext(driver: '', profile: $profileName, strictTools: false),
        );

        if (! $preflight->session instanceof ReaderSession) {
            return PreflightOutcome::refused((string) $preflight->refusal?->detail, $name, $profileName);
        }

        $budget = $this->budgetMs($budgetMs);

        // The migrations this deploy is about to run, linted through the SAME entry point
        // `sqlens:lint` uses. Not a second rule engine and not a second resolution: the lint route
        // already owns resolve → capture → canonicalize → rule, and calling it here is what makes
        // the subset guarantee STRUCTURAL rather than asserted — the ids a predeploy run reports
        // cannot exceed the ids a lint run reports, because they come from the same call.
        //
        // `Pretend` and nothing else. A preflight may not execute a migration, and `Shadow` would
        // both be a second code path and create a database moments before a deploy.
        //
        // Baseline applied, deliberately. A rule a project suppressed stays suppressed here: an
        // answer that differed from CI's would make two runs over the same migrations disagree, and
        // whichever somebody read last would win.
        // Package migrations INCLUDED, and this one is not a preference. `sqlens:lint` leaves them
        // out by default because a finding inside somebody else's package is one a team cannot act
        // on, repeated on every run. A preflight asks a different question: what is this deploy
        // about to walk into. A package's migration runs in that deploy like any other and can take
        // an ACCESS EXCLUSIVE lock like any other, so leaving it out would answer the question
        // wrongly — and `pendingFiles` below is filled from this run, so the subset guarantee would
        // shrink with it, silently.
        $lint = $this->lint->run(
            connection: $name,
            migrationPaths: null,
            mode: CaptureMode::Pretend,
            applyBaseline: true,
            includeVendorMigrations: true,
        );

        $context = new PreflightContext(
            connection: $name,
            driver: $preflight->driver,
            serverVersion: $preflight->serverVersion instanceof ServerVersion
                ? $preflight->serverVersion
                : ServerVersion::of(0, 0, 0, $preflight->driver),
            session: $preflight->session,
            // Filled from the lint run above rather than resolved a second time. Two resolutions
            // would be two answers to "which migrations are pending", and the one that drifted
            // would win silently in whichever half read it.
            //
            // From the RESOLVER, not from the findings. The first version derived the files from
            // the findings' locations, and it was wrong in a way that only shows on a good day: a
            // pending migration no rule has anything to say about produced no finding, so it never
            // appeared here — and a clean deploy looked like an empty one.
            pending: new PendingWork(
                files: $lint->pendingFiles,
                statements: $lint->pendingStatements,
            ),
            profile: $profileName,
            deadlineAt: $deadlineAt = hrtime(true) + ($budget * 1_000_000),
            statistics: $preflight->statistics,
            activity: $preflight->activity,
            migrationRole: $preflight->migrationRole,
            longRunningMs: $this->threshold(self::LONG_RUNNING_KEY, PreflightContext::DEFAULT_LONG_RUNNING_MS),
            replicationLagMs: $this->threshold(self::REPLICATION_LAG_KEY, PreflightContext::DEFAULT_REPLICATION_LAG_MS),
        );

        // Redacted the moment the checks are done and before anything reads them. A database error
        // MESSAGE carries the connection block Laravel appends — host, user, database, the SQL — so
        // a reason that quotes one leaks the target's credentials into every surface at once: the
        // JSON report, the console, and the MCP answer. One place, every check, both callers.
        $report = $this->runner->run($context)->redactedWith(new CredentialRedaction($this->config));

        // Weighed against the live database BEFORE the budget is read off, so the reading it needs
        // comes out of the same budget every check spends rather than out of the slack afterwards.
        $escalation = $this->escalation->applyTo($lint->result->findings, $context);

        $remaining = max(0, (int) round(($deadlineAt - hrtime(true)) / 1_000_000));

        // Read from the SAME call the check judges on: two reads of one fact are two chances to
        // disagree, and the disagreement would surface as a header claiming a bound beside a verdict
        // saying there is none.
        try {
            $timeouts = $this->sessionBounds->inForce($context->driver, $context->session);
        } catch (Throwable) {
            // A header that cannot say is silent rather than optimistic. The check reports the same
            // failure as a named `undetermined`, so nothing is lost by leaving this empty — the run
            // stays fail-closed either way.
            //
            // Read through the `ReadsSessionBounds` seam rather than an inline `new`, which is what
            // makes this arm provable at all: see that interface for why a branch nothing can enter
            // is not caution.
            $timeouts = null;
        }

        return PreflightOutcome::of(
            $name,
            $report,
            $lint,
            $preflight->advisory,
            $timeouts,
            $budget,
            $budget - $remaining,
            $profileName,
            // Both halves travel as ONE result, assembled here rather than by whoever renders it. A
            // finding about a migration and a finding about the instance are the same kind of
            // statement, and two documents would make a consumer choose which one is "the" verdict —
            // so the choice is not offered.
            Result::of([...$escalation->weighed, ...$report->findings(), ...$escalation->unweighed], new RunMetadata(
                serverVersions: [],
                toolVersions: [],
                mode: CaptureMode::Pretend,
                profile: $profileName,
                strictTools: false,
                timeBudgetMsConsumed: $budget - $remaining,
            )),
            $this->runContext->collect($timeouts, $report->describeTimings() ?: null, $budget - $remaining),
        );
    }

    /** The whole run's time budget: the caller's when it named one, else the configured one. */
    private function budgetMs(?int $requested): int
    {
        if ($requested !== null && $requested > 0) {
            return $requested;
        }

        $configured = $this->config->get('sqlens.preflight.budget_ms');

        return is_int($configured) && $configured > 0 ? $configured : 5_000;
    }

    /**
     * A configured preflight threshold, or the shipped default.
     *
     * Falls back on a value it cannot use rather than refusing the run, and that is the right
     * direction here: a threshold is a tuning knob, not a safety boundary. A preflight that declined
     * to run because somebody typed a string would have turned a typo into a stopped deploy, which
     * is worse than judging by the shipped number. `ConfigValidator` is what tells the project the
     * key is wrong; this is what keeps the gate working while they fix it.
     */
    private function threshold(string $key, int $default): int
    {
        $configured = $this->config->get('sqlens.preflight.'.$key);

        return is_int($configured) && $configured > 0 ? $configured : $default;
    }
}
