<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Audit\AuditRuns;
use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\UnsupportedDriverMessage;
use Pushery\SQLens\Exceptions\UnknownReporterFormat;
use Pushery\SQLens\Reporting\ReporterManager;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `sqlens:audit` — the audit suite's shell, and nothing more.
 *
 * It resolves flags, decides what is a misconfiguration BEFORE anything reads a database, hands the
 * run to {@see AuditRuns}, gives the result to a reporter and returns the exit code. It holds no
 * SQL, no driver branch and no rule: everything it could get wrong is a flag, and an architecture
 * test keeps it that way.
 *
 * ## Why every rejection happens before the run
 *
 * An unknown format, an unwritable output file, a level outside 0–9, an unknown category, an
 * unknown profile — each of these is answered as a misconfiguration without connecting to anything.
 * That is not tidiness. A run that reached the database and then failed on its own flags would have
 * opened a connection and set session state on a server the operator had not yet been told they
 * were addressing, and the exit code would arrive after the side effects rather than instead of
 * them.
 *
 * ## The flags it shares with `sqlens:lint`, and the two it does not
 *
 * `--connection`, `--profile`, `--level`, `--category`, `--format`, `--output` and `--strict` mean
 * exactly what they mean there, deliberately: a user who has learned one suite has learned both,
 * and two spellings of one idea is how the suites start behaving differently.
 *
 * `--path`, `--file`, `--pretend`, `--shadow` and `--roundtrip` are absent, and their absence is
 * the point rather than an omission: every one of them is about migration FILES. There is no fast
 * path over a live schema, no pretend mode for a reading that writes nothing anyway, and no
 * rollback to replay. `--ignore-baseline` is here and not there because a baseline over a live
 * schema is the ordinary way a project adopts the audit suite on a database it inherited.
 */
final class AuditCommand extends Command
{
    use ResolvesDebtMode;
    use ResolvesProfile;
    use SharesRunOptions;

    /** @var string */
    protected $signature = 'sqlens:audit
        {--connection= : The database connection to audit; defaults to the resolved sqlens/default connection}
        {--host= : The ONE read host to address when the connection configures a choice; refuses a host it does not offer}
        {--profile= : The environment profile — local, ci, or predeploy. Overrides SQLENS_PROFILE and the configured profile}
        {--level= : The cumulative strictness level 0–9 (defaults to the configured level); security rules run at any level}
        {--category=* : Scope the run to these categories; repeatable and comma-separable (defaults to the configured set; empty = all)}
        {--min-severity= : The security severity floor for this run (info|low|medium|high|critical, or none to report without blocking); beats the profile and the config}
        {--format= : The report format — console, json, github, sarif, or agent (defaults to the configured format)}
        {--output= : Write the report to this file instead of STDOUT}
        {--strict : Treat an undetermined result as a failure — a check that could not run never counts as one that passed}
        {--ignore-baseline : Report every finding, including the ones the baseline accepts}
        {--debt= : What to do with the debts this run finds in the CATALOG — check (the default: compare and report, write nothing) or record (compare, report, and write the reconciled ledger back). A catalog debt has no migration behind it, so its first_seen is the day this project first looked}';

    /** @var string */
    protected $description = 'Audit a connection’s live schema for unsafe, slow, or non-idiomatic design.';

    public function handle(AuditRuns $runner, ReporterManager $reporters, Translator $translator, Repository $config): int
    {
        // BEFORE the reporter, before the profile, before anything opens a connection: is the
        // configuration one this package understands at all? An unknown key is a key that gets
        // IGNORED, and ignoring is silent — a `levl: 3` typo produces a green run that checked
        // less, and nothing on screen says so. The machinery for this existed and was tested from
        // the day it was written; what it never had was a caller.
        if (! $this->configIsValid($config->get('sqlens'))) {
            return ExitCode::Misconfiguration->value;
        }

        // The reporter and the output stream are resolved FIRST: an unknown format or an unwritable
        // path is a misconfiguration that must not cost a connection to discover.
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

        // Everything from here on runs inside the guard, because `--output` is already OPEN and
        // therefore already truncated. Every early return below used to leave a zero-byte file
        // behind that reads like a clean report — so the file is discarded unless a report was
        // actually written into it, and the `finally` is what makes that true of returns nobody
        // has written yet.
        $reported = false;

        try {
            return $this->audit($runner, $reporter, $translator, $config, $output, $reported);
        } finally {
            $reported ? $this->closeReportOutput($output) : $this->discardReportOutput($output);
        }
    }

    /**
     * The run itself, once the reporter and the output stream stand.
     *
     * Split out so the caller's `finally` covers every exit from it — including the ones that
     * return before a single row is read.
     */
    private function audit(
        AuditRuns $runner,
        Reporter $reporter,
        Translator $translator,
        Repository $config,
        OutputInterface $output,
        bool &$reported,
    ): int {
        // Flag over SQLENS_PROFILE over config over the built-in default. An unknown or empty value
        // is named rather than falling back to the lenient default, which would let a run believe
        // it was strict when it was not.
        $profile = $this->resolveProfile($config);

        if (! $profile->isValid()) {
            $this->stderr()->writeln($this->profileRejectionMessage($profile));

            return ExitCode::Misconfiguration->value;
        }

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

        // Named before the run, like every other flag whose wrong value would otherwise be found
        // out after the catalog has been read: an operator who typed `--debt=recrod` believes they
        // recorded something, and a run that quietly checked instead would confirm that belief.
        $debt = $this->validatedDebtMode();

        if ($debt === false) {
            return ExitCode::Misconfiguration->value;
        }

        $connection = $this->option('connection');
        $outcome = $runner->run(
            is_string($connection) && $connection !== '' ? $connection : null,
            // A host is only ever taken from the operator, never inferred. Laravel would pick one at
            // random from a list, and the whole point of this flag is that the choice is a statement
            // somebody made rather than one the framework happened to make.
            is_string($host = $this->option('host')) && $host !== '' ? $host : null,
            $level,
            $categoryValues,
            $this->option('strict') === true ? true : null,
            $this->option('ignore-baseline') === true,
            debt: $debt,
        );

        $failure = $outcome->unsupported;

        if ($failure instanceof DriverResolutionFailure) {
            // An unsupported engine is a message, not a finding: nothing was audited, so there is
            // nothing to report — only to say why, translated and safe to paste.
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
}
