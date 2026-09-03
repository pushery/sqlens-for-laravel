<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Filesystem\Filesystem;
use Pushery\SQLens\Audit\ProjectManifest;
use Pushery\SQLens\Capture\PendingSkipReason;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\PreflightConnection;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\PendingResolver;
use Pushery\SQLens\Contracts\ReadsSessionBounds;
use Pushery\SQLens\Contracts\SessionDefenses;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\CollectedDebt;
use Pushery\SQLens\Deploy\DebtCollector;
use Pushery\SQLens\Deploy\DebtLedger;
use Pushery\SQLens\Deploy\DebtLedgerRefusal;
use Pushery\SQLens\Deploy\DebtNotices;
use Pushery\SQLens\Deploy\DebtState;
use Pushery\SQLens\Deploy\DebtThresholds;
use Pushery\SQLens\Deploy\Drift\DriftExcludeFile;
use Pushery\SQLens\Deploy\Drift\DriftExcludes;
use Pushery\SQLens\Deploy\Drift\DriftReport;
use Pushery\SQLens\Deploy\Drift\ExpectationComparison;
use Pushery\SQLens\Deploy\Drift\ExpectationEscalation;
use Pushery\SQLens\Deploy\Drift\ExpectationReport;
use Pushery\SQLens\Deploy\Drift\ShadowReferenceBuilder;
use Pushery\SQLens\Deploy\PostdeployContext;
use Pushery\SQLens\Deploy\PostdeployVerifier;
use Pushery\SQLens\Deploy\TimeBudgetNotice;
use Pushery\SQLens\Drivers\Capture\DriverCaptorFactory;
use Pushery\SQLens\Drivers\DriverRegistry;
use Pushery\SQLens\Exceptions\UnknownReporterFormat;
use Pushery\SQLens\Exceptions\UnreadableDriftExcludes;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\RunMetadata;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Lint\ShadowClearance;
use Pushery\SQLens\Reporting\ConfigRunContextCollector;
use Pushery\SQLens\Reporting\ReporterManager;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\SubjectContext;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Throwable;

/**
 * What the deploy left behind, read once immediately after `migrate --force`.
 *
 * ## It is the other half of a sentence predeploy starts
 *
 * The gate before a deploy asks "may this run, and is now a good moment". This one asks "did it
 * finish". Those are different questions and the second has no substitute: a `migrate --force` that
 * exits 0 has run every migration it was given, which is not the same as every OBJECT it created
 * being usable. A `CREATE INDEX CONCURRENTLY` that failed leaves an INVALID index behind and does
 * not fail the migration; a constraint added `NOT VALID` whose `VALIDATE` never followed is a
 * promise the database is not keeping. Both are silent, and both survive indefinitely.
 *
 * ## It runs ONCE, and that is structural
 *
 * No `--watch`, no daemon, no scheduler entry, no history. {@see PostdeployVerifier} has no loop and
 * keeps nothing between calls, so "postdeploy is not monitoring" is a property of the code rather
 * than a line in the docs.
 *
 * ## The exit code means something different here
 *
 * Nothing is blocked: the deploy has already happened. The codes are the same contract every other
 * command uses — a pipeline should not have to learn a second one — but a non-zero answer is a
 * report about work already done rather than a refusal to start it. That difference belongs in the
 * deploy recipe, not in a second exit-code scheme.
 */
final class PostdeployCommand extends Command
{
    protected $signature = 'sqlens:postdeploy
        {--connection= : The database connection to verify; defaults to the resolved preflight connection}
        {--profile=postdeploy : The environment profile}
        {--format= : The report format — console, json, github, sarif, or agent (defaults to the configured format)}
        {--budget= : The whole run\'s time budget in milliseconds; the default is configured}
        {--expect-shadow : Also PROVE the schema matches the migrations, by replaying them into a shadow database. Off by default: it creates one, which puts the run behind the production guard}
        {--force : Skip the shadow-replay confirmation; only meaningful with --expect-shadow}
        {--allow-undetermined : Report rather than fail when a check could not answer}';

    protected $description = 'Verify what the deploy left behind: read-only, catalog-only, once.';

    public function handle(
        Repository $config,
        ReaderConnectionFactory $connections,
        PostdeployVerifier $verifier,
        SessionDefenses $defenses,
        CatalogReaderFactory $readers,
        ReporterManager $reporters,
        ConfigRunContextCollector $runContext,
        ReadsSessionBounds $sessionBounds,
        ProjectManifest $manifest,
        DriverRegistry $drivers,
        DriverCaptorFactory $captors,
        PendingResolver $pending,
        ShadowClearance $clearance,
        Application $app,
    ): int {
        $resolution = PreflightConnection::resolve($config);
        $requested = $this->option('connection');
        $name = is_string($requested) && $requested !== '' ? $requested : $resolution->name;

        if ($name === null) {
            // Misconfiguration rather than a finding. Nothing was learned about the database, and a
            // clean answer here would say "your deploy is fine" on the strength of having looked at
            // nothing at all.
            $this->outputErrorLine((string) $resolution->skip?->detail);

            return ExitCode::Misconfiguration->value;
        }

        $profileName = is_string($profile = $this->option('profile')) ? $profile : 'postdeploy';

        $preflight = $connections->forPreflight(
            $defenses,
            $readers,
            new SubjectContext(driver: '', profile: $profileName, strictTools: false),
        );

        if (! $preflight->session instanceof ReaderSession) {
            $this->outputErrorLine((string) $preflight->refusal?->detail);

            return ExitCode::Misconfiguration->value;
        }

        $budgetMs = $this->budgetMs($config);
        $startedAt = hrtime(true);
        $deadlineAt = $startedAt + ($budgetMs * 1_000_000);

        $postdeployContext = new PostdeployContext(
            connection: $name,
            driver: $preflight->driver,
            serverVersion: $preflight->serverVersion instanceof ServerVersion
                ? $preflight->serverVersion
                : ServerVersion::of(0, 0, 0, $preflight->driver),
            session: $preflight->session,
            profile: $profileName,
            deadlineAt: $deadlineAt,
            activity: $preflight->activity,
        );

        $report = $verifier->verify($postdeployContext);

        try {
            $reporter = $reporters->reporter(is_string($format = $this->option('format')) ? $format : null);
        } catch (UnknownReporterFormat $error) {
            // Refused, never fallen back from. A quiet fall back to console succeeds, emits the
            // wrong shape, and leaves whatever was parsing it with nothing.
            $this->outputErrorLine($error->getMessage());

            return ExitCode::Misconfiguration->value;
        }

        // What the CHECKS cost, from the START rather than from what is left of the budget — and
        // measured here, deliberately before the expectation comparison below.
        //
        // ⚠️ `$budgetMs - $remaining` is the obvious spelling and it CANNOT SEE AN OVERRUN.
        // `$remaining` is floored at zero, so a run that took twice its budget and one that took
        // exactly its budget both report the whole budget consumed — the number saturates at the
        // one value that means "on time", and the finding below could never fire. Measured: with
        // that spelling the overrun arm went green against a run that was 60 ms over.
        //
        // `--expect-shadow` is outside this window on purpose. It provisions a database and replays
        // a migration history into it; that cost is dominated by the size of the history rather than
        // by anything this package does, and a budget counting it would fire on every run that asked
        // for the option — a complaint about a cost the user chose, printed beside the answer they
        // chose it for. The budget is about the aftercare that runs unconditionally.
        $consumedMs = (int) round((hrtime(true) - $startedAt) / 1_000_000);

        try {
            // The header says what bounds this run was actually under. A run that IS bounded and
            // does not say so is indistinguishable, in the artifact somebody keeps after a deploy,
            // from one that is not — and this command's whole output is that artifact.
            $timeouts = $sessionBounds->inForce($preflight->driver, $preflight->session);
        } catch (Throwable) {
            // Silent rather than optimistic, exactly as the pre-deploy header is: printing what was
            // ASKED for when the session would not confirm it turns an unknown into a claim.
            $timeouts = null;
        }

        // The expectation comparison, if this run asked for it — and its findings travel in the SAME
        // list as everything else, carrying the same `DEPLOY.DRIFT.*` ids `sqlens:drift` reports.
        //
        // Off by default and that is structural rather than cautious: proving the match means
        // REPLAYING the migrations into a database this command creates, which puts the run behind
        // the production guard. The plain catalog aftercare stays lightweight and guard-free, and a
        // deploy recipe can run it on every deploy without deciding anything.
        $expectation = $this->expectationComparison(
            $config, $captors, $connections, $readers, $pending, $clearance, $app, $name, $profileName,
        );

        // The two-stage promise kept. `DEPLOY.LEGACY.ORPHAN_TRANSITION_OBJECT` and its MySQL twin
        // report a NAME that looks like a leftover, and say in their own words that a name is not
        // evidence and that what would settle it is the object appearing in no migration state at
        // all. This is that second reading, and it is the only thing allowed to promote them.
        $escalation = ExpectationEscalation::apply($report->findings(), $expectation);
        $findings = $escalation['findings'];

        // What the run itself cost, as a finding when it broke the promise — and as NOTHING when it
        // did not. Emitted only on an overrun, and that is what keeps the output deterministic: a
        // wall-clock number in a finding that was always present would make two runs over one
        // unchanged database produce two different documents. The duration still reaches a reader
        // either way, through `run.check_timings` (the split) and `run.time_budget_ms_consumed`
        // (the sum), both excluded from the deterministic comparison by name because both are
        // wall-clock. The second only became true when the field was added to the header — until
        // then this comment named a key the envelope did not emit.
        $overrun = $consumedMs > $budgetMs
            ? [TimeBudgetNotice::exceeded(
                $budgetMs,
                $consumedMs,
                $report->describeTimings(),
                $postdeployContext->driver,
                $name,
                new SubjectContext(driver: $postdeployContext->driver, profile: $profileName, strictTools: false),
            )]
            : [];

        // The debt account, read against the catalog this deploy just touched. After the checks and
        // before the report, so a debt finding travels as a finding through the same reporters,
        // the same axes and the same ordering as every other one.
        $debt = $this->debtPass($config, $postdeployContext, $findings, $manifest, $drivers);

        // Whether the escape hatch actually waived a block, decided BEFORE the report is written so
        // the report can carry it. A waived run and an earned one otherwise share an exit code, a
        // green tick and a document — and "postdeploy passed" then means two different things
        // nobody can separate afterwards. The exit code below reuses this value rather than asking
        // again, so the record and the verdict cannot drift apart.
        $onlyUndetermined = count($report->undetermined()) === count(array_filter(
            $report->results,
            static fn (CheckResult $result): bool => $result->isBlocking(),
        ));

        $waived = $report->blocks()
            && $onlyUndetermined
            && $this->option('allow-undetermined') === true;

        // The same reporters everything else uses, carrying findings as findings. A post-deploy
        // verdict is not a new kind of thing — it is the same three-valued statement about a
        // database, and a private shape would make `downtime_class` and the severity axis stop
        // working in the one report somebody reads while a deploy is still warm.
        $reporter->report(
            Result::of([...$findings, ...$expectation->findings, ...$overrun, ...$debt['findings']], new RunMetadata(
                serverVersions: [],
                toolVersions: [],
                mode: CaptureMode::Pretend,
                profile: $profileName,
                strictTools: false,
                timeBudgetMsConsumed: $consumedMs,
            )),
            $runContext->collect($timeouts, $report->describeTimings() ?: null, $consumedMs)
                ->withUndeterminedWaiver($waived)
                // The comparison as its OWN block rather than mixed into the findings — and present
                // on every run, including the ones that did not compare. A document holding no
                // drift findings says "they agree" and "nobody looked" with the same silence, and
                // the document is what a pipeline archives.
                ->withExpectation($expectation->block()),
            $this->getOutput()->getOutput(),
        );

        foreach ($report->undetermined() as $result) {
            $this->outputErrorLine($result->checkId.': '.$result->reason);
        }

        // Said out loud on every run, whichever way it went. A green post-deploy that did NOT
        // compare against the migrations has proved less than a reader assumes, and the difference
        // between "your schema matches" and "I did not look" is the whole reason this option exists.
        $this->outputErrorLine($expectation->note);

        // A debt old enough to breach `deploy.debt.fail_at` ends the run even when every check
        // passed. It is the one thing in this command that can turn a clean verdict into a failing
        // one, and it does so only because a project asked for it by name.
        if ($debt['breaches']) {
            return ExitCode::FindingsAboveGate->value;
        }

        // Decided BEFORE `blocks()` is consulted, because the comparison is a second source of
        // verdicts and the verifier's report has never heard of it. A `fail` in the document riding
        // on a clean exit code is exactly the silent green this package refuses — and it would be
        // the quietest kind, because the document says the right thing and only the pipeline is
        // told otherwise.
        // The overrun joins the two below rather than sitting quietly in the document, for the
        // reason they are there: a `fail` that a pipeline is never told about is a `fail` nobody
        // acts on. Nothing is blocked either way — the deploy has already happened, and this
        // command's exit code has always been a report about work already done.
        if ($expectation->blocks() || $escalation['promoted'] > 0 || $overrun !== []) {
            return ExitCode::FindingsAboveGate->value;
        }

        // `--expect-shadow` was asked for and could not be answered. That is undetermined, not
        // clean: the run was told to prove the schema matches and did not, so the hatch decides
        // exactly as it does for a check that could not run.
        if ($expectation->requested && ! $expectation->compared && $this->option('allow-undetermined') !== true) {
            return ExitCode::UndeterminedInStrictMode->value;
        }

        if (! $report->blocks()) {
            return ExitCode::Clean->value;
        }

        if ($waived) {
            return ExitCode::Clean->value;
        }

        return $report->undetermined() !== [] && $onlyUndetermined
            ? ExitCode::UndeterminedInStrictMode->value
            : ExitCode::FindingsAboveGate->value;
    }

    /**
     * The shadow replay, and the comparison against it — when this run asked for one.
     *
     * ## Why the whole thing lives behind an option
     *
     * Every other part of this command reads a catalog and nothing else: no lock, no write, no
     * provisioning, guard-free, and cheap enough that a deploy recipe can run it every single time.
     * A comparison against the migrations cannot be any of that — it CREATES a database, replays
     * the migration set into it and drops it again. Making that the default would put the whole
     * command behind the production guard for the sake of one of its answers.
     *
     * ## Every refusal is NAMED, and none of them is a pass
     *
     * A driver with no shadow support, a production connection the guard declined, a migration set
     * that could not be enumerated: each returns an {@see ExpectationReport::unavailable()} carrying
     * its reason, and the caller's exit code treats that as undetermined. The one that would matter
     * most if it were quiet is the middle case — a refusal to touch production is the guard working,
     * and a run that reported it as "no drift" would be advertising the opposite.
     */
    private function expectationComparison(
        Repository $config,
        DriverCaptorFactory $captors,
        ReaderConnectionFactory $connections,
        CatalogReaderFactory $readers,
        PendingResolver $pending,
        ShadowClearance $clearance,
        Application $app,
        string $connectionName,
        string $profileName,
    ): ExpectationReport {
        if ($this->option('expect-shadow') !== true) {
            return ExpectationReport::notRequested();
        }

        $builder = $captors->shadowReference($connectionName, $connections, $readers);

        if (! $builder instanceof ShadowReferenceBuilder) {
            return ExpectationReport::unavailable($builder->reason->value);
        }

        $resolution = $pending->resolve($connectionName);

        if ($resolution->skip instanceof PendingSkipReason) {
            // Not an empty migration set. Treating it as empty would make the expectation side "the
            // database as provisioned", against which every object the migrations added reads as
            // unexpected drift — hundreds of findings, all of them artefacts, and the orphan
            // promotion above would fire on every one of them.
            return ExpectationReport::unavailable('the pending migrations could not be resolved: '
                .$resolution->skip->value);
        }

        $context = new SubjectContext(
            driver: $this->driverFor($config, $connectionName),
            profile: $profileName,
            strictTools: false,
        );

        $schemas = $config->get('sqlens.catalog.schemas');
        $request = new CatalogRequest(
            schemas: is_array($schemas) ? array_values(array_filter($schemas, is_string(...))) : [],
        );

        $catalog = $readers
            ->for($context->driver, $connections->forConnection($connectionName), $connections->budget(), $context)
            ->catalog;

        $comparison = new ExpectationComparison($builder)->run(
            $clearance->decide(
                $connectionName,
                $force = $this->option('force') === true,
                $interactive = $this->input->isInteractive(),
                $force || ! $interactive ? false : $this->confirm('Run the shadow replay against '.$connectionName.'?'),
            ),
            $resolution->migrations,
            $request,
            $context,
            $catalog,
        );

        $drift = $comparison->report;

        if (! $drift instanceof DriftReport) {
            return ExpectationReport::unavailable((string) $comparison->reference?->reason?->value);
        }

        try {
            // The SAME exclude file `sqlens:drift` reads, and the reason is the equivalence this
            // whole path exists for: a difference a project has accepted must not come back as a
            // failure because it arrived through the other command.
            //
            // Staleness is deliberately NOT judged here. `sqlens:drift` ends the run over an entry
            // that covers nothing, because the exclude file is its subject; this command's subject
            // is the deploy that just finished, and refusing to report on it over a rotten line in
            // a config file would withhold the answer somebody is waiting for.
            $drift = DriftExcludes::from(DriftExcludeFile::read($this->excludePath($config, $app)))->applyTo($drift)->report;
        } catch (UnreadableDriftExcludes $refusal) {
            // Unreadable is a different fact from stale, and it is not survivable: an exclude file
            // that cannot be parsed might be excluding anything at all, so a comparison run against
            // it would report an unknown subset as the whole truth.
            return ExpectationReport::unavailable($refusal->getMessage());
        }

        return ExpectationReport::compared($drift, $context, $connectionName);
    }

    /**
     * Where the accepted-differences file lives — literally the same resolution `sqlens:drift`
     * makes, called rather than restated.
     *
     * There is no `--exclude-file` flag here on purpose: the flag is a one-run override for the
     * command whose subject IS the file, and a deploy recipe pointing this command at a different
     * accepted-differences list would be accepting differences somewhere nobody reviews.
     */
    private function excludePath(Repository $config, Application $app): string
    {
        $configured = $config->get('sqlens.deploy.drift.exclude_file');

        return DriftExcludeFile::configuredPath(is_string($configured) ? $configured : null, $app->basePath());
    }

    /**
     * The engine behind a connection NAME, read from the key every other command reads it from.
     *
     * Empty rather than guessed when the connection is not configured: the catalog factory refuses
     * an unknown driver by name, which is a better message than one invented here would be.
     */
    private function driverFor(Repository $config, string $connectionName): string
    {
        $driver = $config->get('database.connections.'.$connectionName.'.driver');

        return is_string($driver) ? $driver : '';
    }

    /**
     * What the committed debt account and the catalog this deploy just touched say about each other.
     *
     * ## Why postdeploy asks at all
     *
     * This is the moment a two-step pattern either closed or did not. The migration that was
     * supposed to validate the constraint has just run; if the catalog still says otherwise, the
     * deploy left an open end behind — and the report somebody reads while the deploy is still warm
     * is the last place that observation is cheap to act on.
     *
     * ## What it never does
     *
     * It does not write. Not to the database, and not to the ledger — a deploy server has a COPY of
     * the repository, not a working copy of it, and editing a committed file from there puts a
     * change into somebody's tree that nobody made, on a machine where nobody can review it. A
     * settled debt is REPORTED as settled; the entry goes on the next repository run.
     *
     * ## Why it returns the verdict alongside the findings
     *
     * Whether a debt is old enough to stop the deploy is a question about the ENTRY — its age, its
     * state — and both are in hand here. Deriving it later from the findings would mean reading the
     * answer back out of a sentence somebody wrote for a human, which is the parsing this package
     * refuses everywhere else: it works until the wording changes, and then it fails silently in
     * the direction of letting a deploy through.
     *
     * @param  list<Finding>  $reported  this run's own findings, which name the debts still owed
     * @return array{findings: list<Finding>, breaches: bool}
     */
    private function debtPass(Repository $config, PostdeployContext $context, array $reported, ProjectManifest $manifest, DriverRegistry $drivers): array
    {
        if ($config->get('sqlens.deploy.debt.enabled') !== true) {
            return ['findings' => [], 'breaches' => false];
        }

        $subject = new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false);
        $configured = $config->get('sqlens.deploy.debt.path');
        $path = is_string($configured) && $configured !== '' ? $configured : DebtLedger::DEFAULT_PATH;
        $ledger = DebtLedger::load(new Filesystem, $manifest->root().'/'.$path);

        if (! $ledger->isUsable()) {
            return ['findings' => [DebtNotices::ledgerUnreadable(
                $ledger->refusal instanceof DebtLedgerRefusal ? $ledger->refusal->detail : 'it could not be read',
                $ledger->refusal instanceof DebtLedgerRefusal ? $ledger->refusal->reason : UndeterminedReason::DebtLedgerUnreadable,
                $context->driver,
                $context->connection,
                $subject,
            )], 'breaches' => false];
        }

        $stillOwed = [];

        foreach ($reported as $finding) {
            if (is_string($finding->location->objectName)) {
                $stillOwed[] = $finding->location->objectName;
            }
        }

        $collected = DebtCollector::collect(
            $ledger,
            $drivers->debtStandingResolverFor($context->driver, $stillOwed, $context->session),
            gmdate('Y-m-d'),
        );

        if ($collected->ledgerMissing) {
            return ['findings' => [DebtNotices::ledgerMissing($path, $context->driver, $context->connection, $subject)], 'breaches' => false];
        }

        $thresholds = DebtThresholds::fromConfig($config->get('sqlens.deploy.debt.thresholds'));
        $failAt = $config->get('sqlens.deploy.debt.fail_at');
        $findings = [];
        $breaches = false;

        foreach ($collected->stillOpen() as $debt) {
            $findings[] = DebtNotices::stillOpen(
                $debt,
                $debt->severity($thresholds, Severity::Info),
                $context->driver,
                $context->connection,
                $subject,
            );

            $breaches = $breaches || $this->breaches($debt, $failAt);
        }

        foreach ($collected->resolved() as $debt) {
            $findings[] = DebtNotices::resolved($debt, $context->driver, $context->connection, $subject);
        }

        foreach ($collected->unresolvable() as $debt) {
            $findings[] = DebtNotices::objectNotFound($debt, $context->driver, $context->connection, $subject);
        }

        return ['findings' => $findings, 'breaches' => $breaches];
    }

    /**
     * Whether one outstanding debt is old enough that this project asked the deploy to stop.
     *
     * Off unless `deploy.debt.fail_at` names a number: debts are a reported state, the safe
     * two-step patterns leave them on purpose, and a deploy command that refused to finish over one
     * would punish exactly the projects doing the right thing.
     *
     * An ACKNOWLEDGED debt never breaks a run, whatever its age. The decision to carry it has been
     * made and written down; overriding that from a config value would make the acknowledgment
     * worthless — which is the one thing that would stop anybody writing a reason down again.
     *
     * An age this build could not read never breaks one either. A threshold compared against an
     * unknown number is a coin toss with a policy's name on it, and the unreadable date is already
     * reported on its own.
     */
    private function breaches(CollectedDebt $debt, mixed $failAt): bool
    {
        if (! is_int($failAt) || $failAt < 1) {
            return false;
        }

        if ($debt->entry->state === DebtState::Acknowledged || ! $debt->age->isKnown()) {
            return false;
        }

        return (int) $debt->age->days() >= $failAt;
    }

    /** Everything that is not the report goes to STDERR, so `--format=json` leaves STDOUT parseable. */
    private function outputErrorLine(string $line): void
    {
        $output = $this->getOutput()->getOutput();

        ($output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output)->writeln($line);
    }

    /**
     * The run's budget.
     *
     * Shares `sqlens.preflight.budget_ms` on purpose: it is the same session, the same reader and
     * the same promise about not outstaying its welcome on a live instance. A second key would be a
     * second number to keep in step, and the day they differed nobody could say which one a deploy
     * recipe was honoring.
     */
    private function budgetMs(Repository $config): int
    {
        $requested = $this->option('budget');

        if (is_string($requested) && ctype_digit($requested) && (int) $requested > 0) {
            return (int) $requested;
        }

        // The POST-deploy key, not the pre-deploy one. This command read `preflight.budget_ms` until
        // 2026-08-24, so raising the gate's allowance silently raised the aftercare's too and
        // lowering it silently squeezed a run that had nothing to do with the change. Two commands
        // making two promises need two numbers.
        $configured = $config->get('sqlens.deploy.postdeploy.budget_ms');

        return is_int($configured) && $configured > 0 ? $configured : 5_000;
    }
}
