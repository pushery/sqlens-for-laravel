<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Capture\SingleFileFailure;
use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\UnsupportedDriverMessage;
use Pushery\SQLens\Exceptions\UnknownReporterFormat;
use Pushery\SQLens\Exceptions\UnreadableBaseline;
use Pushery\SQLens\Lint\LintRunner;
use Pushery\SQLens\Lint\ShadowClearance;
use Pushery\SQLens\Reporting\Console\ConsoleReporter;
use Pushery\SQLens\Reporting\ReporterManager;
use Pushery\SQLens\Subjects\CaptureMode;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `sqlens:lint` — the backbone of the lint suite. It is deliberately thin: it
 * translates options into a run and a run's result into a report, and owns no
 * pipeline logic of its own. The whole resolve → capture → canonicalize → rule →
 * report pipeline lives in the LintRunner, so the command stays driver-free and the
 * same logic is reachable without a console.
 *
 * Three promises reach the exit code, not just the screen: an unsupported engine
 * returns the misconfiguration code with a translated message (and no per-migration
 * noise), an undetermined run in strict mode never returns 0, and a gate breach
 * returns the findings code — the three-valued verdict all the way out.
 *
 * The report goes to STDOUT (or `--output`), and everything else — a warning, an
 * unsupported message, a bad-format error — goes to STDERR, so `--format=json`
 * leaves STDOUT with nothing but the JSON document a pipeline can parse.
 */
final class LintCommand extends Command
{
    use ResolvesDebtMode;
    use ResolvesProfile;
    use ResolvesStrictTools;
    use SharesRunOptions;

    /** @var string */
    protected $signature = 'sqlens:lint
        {--connection= : The database connection to lint; defaults to the resolved sqlens/default connection}
        {--path=* : A migration path to lint; repeatable. Defaults to the application’s registered migration paths}
        {--file=* : Lint exactly one migration file — the DB-free fast path for pre-commit hooks. Must be inside a configured migration path}
        {--profile= : The environment profile — local, ci, or predeploy. Overrides SQLENS_PROFILE and the configured profile}
        {--level= : The cumulative strictness level 0–9 (defaults to the configured level); security rules run at any level}
        {--category=* : Scope the run to these categories; repeatable and comma-separable (defaults to the configured set; empty = all)}
        {--min-severity= : The security severity floor for this run (info|low|medium|high|critical, or none to report without blocking); beats the profile and the config}
        {--format= : The report format — console, json, github, sarif, or agent (defaults to the configured format)}
        {--show-remediation : Expand the fix sequence under each console finding instead of the one-line hint; console format only}
        {--output= : Write the report to this file instead of STDOUT}
        {--assume-server-version= : Reason about this server version instead of the detected one — the determinism pin for CI}
        {--strict-tools : Treat a missing external tool as an error, not a degradation (overrides the configured strict_tools)}
        {--no-strict-tools : Treat a missing external tool as a degradation (overrides the configured strict_tools)}
        {--pretend : Collect each migration’s SQL without executing it (the default, do-no-harm mode)}
        {--shadow : Run each migration for real against a throwaway shadow database (behind the production guard)}
        {--roundtrip : Replay up → down → up in the throwaway database to test that down() is a real inverse (shadow only)}
        {--force : Confirm a shadow run without being asked; it never overrides the allowed-environment check}
        {--debt= : What to do with the migration debt account — check (the default: compare and report, write nothing) or record (compare, report, and write the reconciled ledger back)}';

    /** @var string */
    protected $description = 'Lint the pending migrations of a connection for unsafe schema changes.';

    public function handle(LintRunner $runner, ReporterManager $reporters, Translator $translator, Repository $config, ShadowClearance $clearance): int
    {
        // BEFORE the reporter, before the profile, before anything opens a connection: is the
        // configuration one this package understands at all? An unknown key is a key that gets
        // IGNORED, and ignoring is silent — a `levl: 3` typo produces a green run that checked
        // less, and nothing on screen says so. The machinery for this existed and was tested from
        // the day it was written; what it never had was a caller.
        if (! $this->configIsValid($config->get('sqlens'))) {
            return ExitCode::Misconfiguration->value;
        }

        // Resolve the reporter and the output stream BEFORE the run, so an unknown
        // format or an unwritable output file fails fast as a misconfiguration without
        // capturing anything.
        $format = $this->option('format');

        try {
            $reporter = $reporters->reporter(is_string($format) && $format !== '' ? $format : null);

            // Console only, and the `instanceof` says so honestly rather than hiding it. The other
            // four formats carry the whole payload already — JSON and agent by design, SARIF and
            // GitHub by a documented refusal — so a switch that "worked" for them would either do
            // nothing or promise something the format does not offer.
            if ($this->option('show-remediation') === true && $reporter instanceof ConsoleReporter) {
                $reporter = $reporter->showingRemediationSteps();
            }
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

        // The lint half of the same hazard. `--output` is open and therefore already
        // truncated, and this command has NINE early returns after this point: a bad profile, a bad
        // level, a bad category, two `--file` conflicts, three `--roundtrip` refusals, a blocked
        // production guard. Every one of them used to leave a zero-byte report behind that reads
        // like a clean run. The `finally` covers the tenth too.
        $reported = false;

        try {
            return $this->lint($runner, $reporter, $translator, $config, $clearance, $output, $reported);
        } finally {
            $reported ? $this->closeReportOutput($output) : $this->discardReportOutput($output);
        }
    }

    /**
     * The run itself, once the reporter and the output stream stand.
     *
     * Split out so the caller's `finally` covers every exit from it — including the ones that
     * return before a single migration is read.
     */
    private function lint(
        LintRunner $runner,
        Reporter $reporter,
        Translator $translator,
        Repository $config,
        ShadowClearance $clearance,
        OutputInterface $output,
        bool &$reported,
    ): int {
        // The active profile is resolved BEFORE the run — flag over SQLENS_PROFILE over
        // config over the built-in default — and an unknown or empty value is named,
        // never a silent fall back to the lenient default that would let a run believe
        // it was strict when it was not. A valid selection is written to config, so the
        // header and the profile overrides all see the profile the user chose.
        $profile = $this->resolveProfile($config);

        if (! $profile->isValid()) {
            $this->stderr()->writeln($this->profileRejectionMessage($profile));

            return ExitCode::Misconfiguration->value;
        }

        // An out-of-range or non-numeric level is a misconfiguration named before the
        // run, not a value quietly clamped into something the user did not ask for.
        $level = $this->validatedLevel();

        if ($level === false) {
            return ExitCode::Misconfiguration->value;
        }

        $categoryValues = $this->validatedCategories();

        if ($categoryValues === false) {
            return ExitCode::Misconfiguration->value;
        }

        // The severity floor, layered ON TOP of the profile the trait above already baked into the
        // config — which is what makes the precedence config → profile → flag hold without the
        // threshold traveling twice. Written to the key every reader consults rather than passed
        // as a parameter, for the same reason the resolved profile is.
        $minSeverity = $this->validatedMinSeverity();

        if ($minSeverity === false) {
            return ExitCode::Misconfiguration->value;
        }

        if ($minSeverity !== null) {
            $config->set('sqlens.security.min_severity', $minSeverity);
        }

        // The --file fast path takes exactly one migration and is pretend-only: more
        // than one file, or --file with --shadow, is a misconfiguration named before
        // the run, not a silent partial.
        $fileValue = null;
        $rawFiles = $this->option('file');

        // Declared `--file=*`, so this is an array by construction; only emptiness is a real
        // question here.
        if ($rawFiles !== []) {
            $files = array_values(array_filter($rawFiles, is_string(...)));

            if (count($files) > 1) {
                $this->stderr()->writeln($this->translate('sqlens::messages.commands.file_multiple'));

                return ExitCode::Misconfiguration->value;
            }

            if ($this->option('shadow') === true) {
                $this->stderr()->writeln($this->translate('sqlens::messages.commands.file_shadow_conflict'));

                return ExitCode::Misconfiguration->value;
            }

            $fileValue = $files[0];
        }

        // The debt mode, named before the run like every other flag whose wrong value would
        // otherwise be quietly reinterpreted. `check` is the default because an ordinary lint must
        // not edit a committed file — a tool that put its own opinion into version control without
        // being asked is one whose next diff nobody trusts.
        $debt = $this->validatedDebtMode();

        if ($debt === false) {
            return ExitCode::Misconfiguration->value;
        }

        $connection = $this->option('connection');
        $roundtrip = $this->option('roundtrip') === true;

        // --roundtrip is locked to shadow mode in CODE, not by documentation. It
        // replays down() for real, which is destructive by design, so it exists only
        // where a database may be broken: the throwaway one it creates itself. Each
        // refusal is named before anything runs — and none of them is a silent drop of
        // the flag, which would let a user believe a roundtrip happened.
        if ($roundtrip) {
            $refusal = match (true) {
                $fileValue !== null => 'roundtrip_file_conflict',
                $this->option('shadow') !== true => 'roundtrip_requires_shadow',
                is_string($connection) && $connection !== '' => 'roundtrip_connection_conflict',
                default => null,
            };

            if ($refusal !== null) {
                $this->stderr()->writeln($this->translate('sqlens::messages.commands.'.$refusal));

                return ExitCode::Misconfiguration->value;
            }
        }

        $shadow = $fileValue === null && $this->option('shadow') === true;

        // Shadow mode creates and drops a database, so the production guard decides
        // BEFORE anything is built — and its decision is passed down rather than
        // re-derived, so there is exactly one guard. A blocked decision still runs:
        // the captor turns it into a named undetermined per migration, which is the
        // honest report of a run that was not allowed, never a silent nothing.
        $guard = $shadow ? $this->guardDecision($clearance, $config, $connection) : null;
        $assume = $this->option('assume-server-version');

        // A baseline that cannot be read stops the run HERE, named, with the misconfiguration exit.
        // The alternative is what this used to do: treat it as empty, so every accepted finding
        // comes back at once and the reader sees a wall of new findings with nothing saying the
        // file was unreadable. Loud for the wrong reason is not better than quiet.
        try {
            $outcome = $runner->run(
                is_string($connection) ? $connection : null,
                $this->migrationPaths(),
                $shadow ? CaptureMode::Shadow : CaptureMode::Pretend,
                is_string($assume) && $assume !== '' ? $assume : null,
                $level,
                $categoryValues,
                strictTools: $this->strictToolsOverride(),
                file: $fileValue,
                guard: $guard,
                roundtrip: $roundtrip,
                debt: $debt,
            );
        } catch (UnreadableBaseline $failure) {
            $this->stderr()->writeln($failure->getMessage());

            return ExitCode::Misconfiguration->value;
        }

        // A --file that did not resolve to a migration is a named misconfiguration.
        if ($outcome->fileFailure instanceof SingleFileFailure) {
            $this->stderr()->writeln($this->translate($outcome->fileFailure->translationKey(), ['file' => (string) $fileValue]));

            return $outcome->exitCode->value;
        }

        $failure = $outcome->unsupported;

        if ($failure instanceof DriverResolutionFailure) {
            // An unsupported engine is a message, not a finding: nothing was linted, so
            // there is nothing to report — only to say why, translated and safe to paste.
            $driver = $config->get("database.connections.{$outcome->connectionName}.driver");

            $this->stderr()->writeln(new UnsupportedDriverMessage($translator)->for(
                $failure,
                $outcome->connectionName,
                is_string($driver) ? $driver : 'unknown',
            ));

            return $outcome->exitCode->value;
        }

        $reporter->report($outcome->result, $outcome->context, $output);
        $reported = true;

        return $outcome->exitCode->value;
    }

    /**
     * The production guard's decision for a shadow run.
     *
     * The GATHERING moved to {@see ShadowClearance}, because a second caller — the MCP tool — needs
     * the same verdict and a second gathering would be a second answer to "which environments are
     * allowed". What stays here is the part that is genuinely the command's: `--force`, whether a
     * terminal is attached, and the question a person can answer.
     *
     * A non-interactive run without `--force` is refused rather than assumed-yes.
     */
    private function guardDecision(ShadowClearance $clearance, Repository $config, mixed $connection): GuardDecision
    {
        $configuredDefault = $config->get('database.default');
        $connectionName = is_string($connection) && $connection !== ''
            ? $connection
            : (is_string($configuredDefault) ? $configuredDefault : '');

        $force = $this->option('force') === true;
        $interactive = $this->input->isInteractive();

        return $clearance->decide(
            $connectionName,
            $force,
            $interactive,
            // Only asked when it can change the answer: --force is already the explicit
            // yes, and a non-interactive run has nobody to ask.
            $force || ! $interactive
                ? false
                : $this->confirm($this->translate('sqlens::messages.shadow.confirm', ['connection' => $connectionName])),
        );
    }

    /**
     * The migration paths to lint: the repeated `--path` options, or null (the
     * runner's default) when none are given. Null is NOT an empty list — an empty
     * list means "explicitly no paths" and skips; null means "the app's defaults".
     *
     * @return list<string>|null
     */
    private function migrationPaths(): ?array
    {
        $paths = $this->option('path');

        // No `is_array()` guard: the option is declared `--path=*`, so Symfony hands back an
        // array or nothing else. A check PHPStan can prove always true is a branch no test can
        // reach and no reader can trust — it reads as defensiveness while defending nothing.
        if ($paths === []) {
            return null;
        }

        return array_values(array_filter($paths, is_string(...)));
    }
}
