<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Catalog\Security\SecurityNotice;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Config\ProfileSelection;
use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Exceptions\UnknownReporterFormat;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\RunMetadata;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\PackageVersion;
use Pushery\SQLens\Reporting\CaptureMode;
use Pushery\SQLens\Reporting\ConfigRunContextCollector;
use Pushery\SQLens\Reporting\ReporterManager;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\RunProfile;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Security\Advisory\AdvisoryRefresher;
use Pushery\SQLens\Security\SecurityOutcome;
use Pushery\SQLens\Security\SecurityRunner;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\CaptureMode as SubjectCaptureMode;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `sqlens:security` — the security and privacy suite's front door.
 *
 * It orchestrates the sub-runs (roles and authentication, privileges, server configuration,
 * row-level security, injection, unencrypted columns), applies the severity gate, rolls the
 * three-valued results up, and hands the whole run to the selected reporter.
 *
 * ## A run that checked nothing never reports a pass
 *
 * The oldest guarantee in this file, and the one that has outlived every other line of it. A
 * command that resolves its flags, finds nothing to run, and exits quietly with a zero is
 * indistinguishable from one that examined a database and found it sound — and the second reading
 * is the one a person makes. So a run whose filters admit no rule ends in an `undetermined`
 * finding carrying {@see SecurityNotice::NothingChecked} and a sentence saying what did not happen.
 *
 * ## Why an undetermined is not automatically a failure
 *
 * It moves the exit code only under `strict_undetermined`, and that is the project's decision
 * rather than this command's. On a managed database a large share of what this suite reads is
 * simply not exposed to any role a customer can hold, so a suite that failed outright on every
 * unanswerable question would be unusable exactly where it is most needed. The report says what
 * happened; the strict flag decides what it costs. `--allow-undetermined` overrides it for one
 * run and hides nothing — every undetermined stays in the report, counted and with its reason.
 *
 * ## Nothing here guesses
 *
 * `--connection` addresses an instance explicitly, `--profile` selects the environment profile,
 * `--min-severity` sets the floor, `--format` picks the reporter. An unknown value for any of them
 * is a misconfiguration named before anything connects — never a quiet fall back to `default`, to
 * `local`, or to the console reporter, which would run a different check from the one that was
 * asked for and then report it as the one that was asked for.
 *
 * ## The severity axis, not the level
 *
 * Security and privacy findings ignore the cumulative strictness level entirely. A level is an
 * appetite for rigor, and a role without a password is not a matter of appetite. The floor is
 * `security.min_severity`, and it is the one default in this package that does not ship at its
 * most lenient value — the `ci` and `predeploy` profiles pin it rather than inherit it, so a
 * project that lowers its own floor while working through a backlog cannot end up with a pipeline
 * that silently blocks on nothing.
 */
final class SecurityCommand extends Command
{
    use ResolvesMinSeverity;
    use ResolvesProfile;
    use ResolvesStrictTools;

    // Adopted now that `--format` and `--output` arrive. This command's byte-identical copies of
    // `configIsValid()` and `stderr()` are gone with them; what it cannot take is SharesRunOptions
    // itself, whose validators read flags this command deliberately does not offer.
    use WritesReportOutput;

    /** @var string */
    protected $signature = 'sqlens:security
        {--connection= : The database connection to examine; defaults to the resolved sqlens/default connection}
        {--profile= : The environment profile — local, ci, or predeploy. Overrides SQLENS_PROFILE and the configured profile}
        {--allow-undetermined : Do not let an undetermined check move the exit code, even under strict_undetermined. It hides nothing — every undetermined stays in the report, counted and with its reason}
        {--strict-tools : Treat a missing external tool as an error, not a degradation (overrides the configured strict_tools)}
        {--no-strict-tools : Treat a missing external tool as a degradation (overrides the configured strict_tools)}
        {--refresh-advisories : Fetch the end-of-life data from the configured source and write it where this package reads it. The ONLY thing here that touches the network, and never a side effect of a check}
        {--host= : The ONE read host to address when the connection configures a choice; refuses a host it does not offer}
        {--min-severity= : The security severity floor for this run (info|low|medium|high|critical, or none to report without blocking); beats the profile and the config}
        {--format= : The report format — console, json, github, sarif, or agent (defaults to the configured format)}
        {--output= : Write the report to this file instead of STDOUT}';

    /** @var string */
    protected $description = 'Examine a connection for security and privacy findings across every suite.';

    public function handle(SecurityRunner $runner, ReporterManager $reporters, ExitCodeResolver $exitCodes, Repository $config): int
    {
        // Before anything else, and before anything connects. An unknown config key is a key that
        // gets IGNORED, and ignoring is silent — a typo produces a run that checked less, with
        // nothing on screen to say so.
        if (! $this->configIsValid($config->get('sqlens'))) {
            return ExitCode::Misconfiguration->value;
        }

        // Beside it, and for the same reason: a name that resolves to nothing is a run that
        // examined something other than what the project asked for.
        if ($this->refuseUnknownAuditConnection($config)) {
            return ExitCode::Misconfiguration->value;
        }

        // BEFORE the profile, the reporter and anything that connects — a refresh is not a check
        // and shares none of a check's setup. Running it through them would make an unreachable
        // database a reason the data cannot be refreshed, which is exactly backwards: refreshing is
        // what somebody does when the check told them the data was old.
        if ($this->option('refresh-advisories') === true) {
            return $this->refreshAdvisories();
        }

        $profile = $this->resolveProfile($config);

        if (! $profile->isValid()) {
            $this->stderr()->writeln($this->profileRejectionMessage($profile));

            return ExitCode::Misconfiguration->value;
        }

        // The severity floor, layered ON TOP of the profile the resolver above already baked into
        // the config — which is what makes the precedence config → profile → flag hold without the
        // threshold traveling twice. Written to the key every reader consults rather than passed
        // as a parameter, exactly as `sqlens:lint` does it: the audit half builds its own context
        // deep inside the run, and a parameter would have to be threaded there to be seen.
        $minSeverity = $this->validatedMinSeverity();

        if ($minSeverity === false) {
            return ExitCode::Misconfiguration->value;
        }

        if ($minSeverity !== null) {
            $config->set('sqlens.security.min_severity', $minSeverity);
        }

        // The reporter and the output stream are resolved FIRST, the same order the other suites
        // use: an unknown format or an unwritable path is a misconfiguration, and discovering it
        // should not cost a connection — let alone a full catalog read against production.
        $format = $this->option('format');

        try {
            $reporter = $reporters->reporter(is_string($format) && $format !== '' ? $format : null);
        } catch (UnknownReporterFormat $exception) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.unknown_format', [
                'format' => $exception->requested,
                'available' => implode(', ', $exception->available),
            ]));

            return ExitCode::Misconfiguration->value;
        }

        $output = $this->reportOutput();

        if (! $output instanceof OutputInterface) {
            return ExitCode::Misconfiguration->value;
        }

        // From here on `--output` is already OPEN and therefore already TRUNCATED. A run that
        // returns early past this point would leave a zero-byte file behind, and a zero-byte
        // report reads exactly like a clean one — this suite's own silent green, written to disk.
        // So the file is discarded unless a report was genuinely written into it, and the
        // `finally` is what makes that true of every exit, including ones nobody has written yet.
        $reported = false;

        try {
            return $this->examine($runner, $reporter, $exitCodes, $config, $profile, $output, $reported);
        } finally {
            $reported ? $this->closeReportOutput($output) : $this->discardReportOutput($output);
        }
    }

    /**
     * The run itself, once the reporter and the output stream stand.
     *
     * Split out so the caller's `finally` covers every exit from it, the same shape `sqlens:audit`
     * uses. `$reported` is by reference rather than returned because the caller needs it on the
     * path where this method THROWS — which is the path where a truncated file would otherwise
     * survive as a report nobody wrote.
     */
    private function examine(
        SecurityRunner $runner,
        Reporter $reporter,
        ExitCodeResolver $exitCodes,
        Repository $config,
        ProfileSelection $profile,
        OutputInterface $output,
        bool &$reported,
    ): int {
        $connection = $this->auditConnection($config);
        $host = $this->option('host');
        $strictTools = $this->strictToolsOverride();
        $strictUndetermined = $this->strictUndetermined($config);
        $outcome = $runner->run(
            $connection,
            null,
            $strictUndetermined,
            $strictTools,
            is_string($host) && $host !== '' ? $host : null,
        );

        // The audit's context when the audit ran, and this command's own when it did not. Never a
        // merge of the two: the audit's carries an instance identity and a server version that a
        // fabricated one would have to invent, and inventing them is how a report starts describing
        // a machine it never reached.
        $context = $outcome->context ?? $this->runContext($config, RunProfile::from((string) $profile->profile), $strictUndetermined, $strictTools);

        $result = Result::of($this->findings($outcome, $context, $this->addressedConnection($config)), $this->metadata($context));

        $reporter->report($result, $context, $output);
        $reported = true;

        // Clean, not because anything was clean — because an undetermined moves the exit code only
        // under `strict_undetermined`, which is the project's decision and not this command's. The
        // report is where the run says what it did; this number says what it costs.
        return $exitCodes->resolve($result, $context)->value;
    }

    /**
     * The refresh, and the reason it returns instead of continuing into a run.
     *
     * A refresh followed by a check in one invocation would report findings from data that changed
     * halfway through the command, and the report's own header could name only one of the two files.
     * So this is the whole command when it is asked for: fetch, validate, write, say what moved.
     *
     * `illuminate/http` is a declared dependency rather than a soft one. Keeping it out to spare
     * consumers an HTTP stack was the first plan, and the repository's own guards refused it: a
     * component the shipped code imports is a component the package requires, and a soft dependency
     * would have been the same weight with the declaration missing.
     */
    private function refreshAdvisories(): int
    {
        $outcome = $this->laravel->make(AdvisoryRefresher::class)->refresh();

        if (! $outcome->succeeded()) {
            $this->stderr()->writeln('The advisory data was NOT refreshed: '.$outcome->reason);

            return ExitCode::Misconfiguration->value;
        }

        if (! $outcome->written) {
            $this->output->writeln(sprintf('The advisory source agrees with %s — nothing to commit.', (string) $outcome->path));

            return ExitCode::Clean->value;
        }

        // The diff, and it is the point of the command rather than decoration: this file is meant to
        // be committed, and a reviewer needs to see that PostgreSQL 14's end date moved rather than
        // that line 87 changed.
        $this->output->writeln(sprintf('Wrote %s:', (string) $outcome->path));

        foreach ($outcome->changes as $change) {
            $this->output->writeln('  '.$change);
        }

        return ExitCode::Clean->value;
    }

    /**
     * Whether an undetermined check moves the exit code on this run.
     *
     * `--allow-undetermined` is the pre-deploy escape hatch: a deploy window is a bad moment to be
     * blocked by a check that could not run, and somebody standing at the console can weigh that.
     * It returns `false` — a decision AGAINST strictness, not the `null` that would leave the
     * configured value alone — because the flag's whole purpose is to beat a strict project config.
     *
     * It changes the exit code and nothing else. Every undetermined finding stays in the report
     * with its named reason and stays in the counts, so the run still says what it could not
     * examine; only the number it exits with stops treating that as a failure. A flag that also
     * suppressed the findings would be a way to make a run look clean, which is the opposite of
     * what an escape hatch is for.
     */
    private function strictUndetermined(Repository $config): ?bool
    {
        if ($this->option('allow-undetermined') === true) {
            return false;
        }

        return $config->get('sqlens.strict_undetermined') === true ? true : null;
    }

    /**
     * Everything this run found, plus the one sentence it owes when it found nowhere to look.
     *
     * The notice is added only when BOTH halves failed. One half that could not run already says so
     * through its own finding, and repeating it at the aggregate level would report one absence
     * twice — while a run where neither half happened has no finding of its own to carry the fact
     * that nothing at all was examined.
     *
     * @return list<Finding>
     */
    private function findings(SecurityOutcome $outcome, RunContext $context, string $connection): array
    {
        return $outcome->examinedNothing()
            ? [...$outcome->findings, $this->nothingChecked($context, $connection)]
            : $outcome->findings;
    }

    /**
     * The finding for a run that found nowhere to look at all.
     *
     * A line on stderr is read by a person and by nobody else. This run's output is consumed by a
     * gate, a baseline and a report diff, and all three have to see that nothing was checked — a
     * console sentence beside an empty result set would tell the person one thing and every machine
     * the opposite.
     */
    private function nothingChecked(RunContext $context, string $connection): Finding
    {
        return Finding::undetermined(
            SecurityNotice::NothingChecked->id(),
            SecurityNotice::MESSAGE_PREFIX,
            'No security check ran: neither the live-catalog half nor the migration half of this run '
            .'could happen, so nothing about this connection was examined. This is not a clean '
            .'result — each half names its own reason above.',
            UndeterminedReason::NotConfigured,
            // The connection, named as the subject: what was NOT examined is the thing a reader
            // needs, and an unnamed subject would leave the finding true of nothing in particular.
            Location::inCatalog(
                'unknown',
                $connection,
                $connection,
                SchemaObjectType::Database,
            ),
            Category::Security,
            Level::Capturable,
            StabilityTier::Stable,
            RuleDocumentationUrl::for(SecurityNotice::NothingChecked->id()),
            new SubjectContext(
                driver: 'unknown',
                profile: $context->profile->value,
                strictTools: $context->strictTools,
            ),
        );
    }

    /**
     * The connection this run examines: the flag, else the project's setting, else the run's own.
     *
     * ONE resolution rather than two reads of `--connection`. The report used to answer that option
     * directly, which was right while the option was the only way in — and would have become a lie
     * the moment `sqlens.security.audit_connection` existed: the header would say `default` while
     * the readers examined a least-privilege connection somewhere else entirely. On a read/write
     * split that is not a cosmetic difference; a replica answers with different server variables,
     * so which instance was examined is a statement about the findings.
     *
     * The flag wins, because a run somebody typed is a decision about THAT run.
     */
    private function auditConnection(Repository $config): ?string
    {
        $flag = $this->option('connection');

        if (is_string($flag) && $flag !== '') {
            return $flag;
        }

        $configured = $config->get('sqlens.security.audit_connection');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }

    /** Which connection this run was pointed at, named for the report. */
    private function addressedConnection(Repository $config): string
    {
        return $this->auditConnection($config) ?? 'default';
    }

    /**
     * Refuse a configured connection no database config defines.
     *
     * A MISCONFIGURATION rather than a fall back, and the distinction is the whole point of the
     * setting: falling back would examine the run's own connection — the application role, with the
     * application's rights — and report the result as if the audit connection had been used. The
     * findings would be real and about the wrong instance.
     *
     * Only the CONFIGURED name is checked here, and only when it is the one this run will actually
     * use. `--connection` overrides it, and a setting the run never reads must not be able to stop
     * it — the first version of this check did exactly that, and the arm that caught it is the one
     * asserting the flag wins. A flag naming an unknown connection fails at the connection manager
     * with Laravel's own message, which already names it.
     */
    private function refuseUnknownAuditConnection(Repository $config): bool
    {
        $configured = $config->get('sqlens.security.audit_connection');

        if (! is_string($configured) || $configured === '') {
            return false;
        }

        if ($this->auditConnection($config) !== $configured) {
            return false;
        }

        if ($config->get('database.connections.'.$configured) !== null) {
            return false;
        }

        $this->stderr()->writeln(sprintf(
            'sqlens.security.audit_connection names "%s", which config/database.php does not define. '
            .'Refused rather than falling back: the run would examine a different instance and report it as clean.',
            $configured,
        ));

        return true;
    }

    /**
     * The run parameters, from the shared value type rather than assembled here.
     *
     * The scaffold's own guard rail: the reproducibility header belongs to the reporting layer, and
     * a command that built a second one would give one run two headers that drift. This consumes it
     * and adds nothing.
     */
    private function runContext(Repository $config, RunProfile $profile, ?bool $strictUndetermined, ?bool $strictTools): RunContext
    {
        return new RunContext(
            serverVersions: [],
            toolVersions: [],
            // Static: this command reads, and captures no migration. Saying "pretend" would claim a
            // simulation that did not happen.
            mode: CaptureMode::Static,
            profile: $profile,
            // The per-run overrides, resolved against the configuration. This context is the one
            // used when the audit half never ran, and that is exactly the run where a dropped
            // override would matter most: nothing examined anything, and the header would still
            // state the configured strictness as though it had been in force.
            strictTools: $strictTools ?? $config->get('sqlens.strict_tools') === true,
            strictUndetermined: $strictUndetermined ?? $config->get('sqlens.strict_undetermined') === true,
            roundtrip: false,
            sqlensVersion: PackageVersion::current(),
            // The security severity floor. This context is the one used when the audit half never
            // ran, and leaving it out is not a missing nicety: the header PRINTS this value, so
            // every such report stated `min-severity=off` as a fact while the project or the flag
            // said otherwise — and the same wrong value went into the JSON envelope, which is
            // public API. The audit had this exact defect and it was fixed there; this is the same
            // one, one command over.
            //
            // tryFrom, not from: a malformed value must not throw mid-run. The config validator
            // owns bad input loudly and separately, so this path stays lenient.
            // One line: a standalone `: null,` is a line coverage can never mark as executed.
            minSeverity: is_string($floor = $config->get('sqlens.security.min_severity')) ? Severity::tryFrom($floor) : null,
            // Zero active rules, and it is the honest number rather than an omission: no rule ran,
            // which is exactly what the finding above says in prose.
            activeRuleCount: 0,
            guardProfile: ConfigRunContextCollector::guardProfileFrom($config),
        );
    }

    private function metadata(RunContext $context): RunMetadata
    {
        return new RunMetadata(
            serverVersions: [],
            toolVersions: [],
            mode: SubjectCaptureMode::Pretend,
            profile: $context->profile->value,
            strictTools: $context->strictTools,
            timeBudgetMsConsumed: 0,
        );
    }
}
