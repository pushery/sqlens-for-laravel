<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Pushery\SQLens\Capture\PendingSkipReason;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Contracts\PendingResolver;
use Pushery\SQLens\Deploy\Drift\DriftClass;
use Pushery\SQLens\Deploy\Drift\DriftExcludeEntry;
use Pushery\SQLens\Deploy\Drift\DriftExcludeFile;
use Pushery\SQLens\Deploy\Drift\DriftExcludes;
use Pushery\SQLens\Deploy\Drift\DriftExitPolicy;
use Pushery\SQLens\Deploy\Drift\DriftFindings;
use Pushery\SQLens\Deploy\Drift\DriftReport;
use Pushery\SQLens\Deploy\Drift\DriftRunMode;
use Pushery\SQLens\Deploy\Drift\ExpectationComparison;
use Pushery\SQLens\Deploy\Drift\ShadowReferenceBuilder;
use Pushery\SQLens\Drivers\Capture\DriverCaptorFactory;
use Pushery\SQLens\Exceptions\UnknownReporterFormat;
use Pushery\SQLens\Exceptions\UnreadableDriftExcludes;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\RunMetadata;
use Pushery\SQLens\Lint\ShadowClearance;
use Pushery\SQLens\Reporting\ConfigRunContextCollector;
use Pushery\SQLens\Reporting\ReporterManager;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Symfony\Component\Console\Output\ConsoleOutputInterface;

/**
 * `sqlens:drift` — what the database holds against what the migrations describe.
 *
 * ## It REPORTS by default, and that is the decision the feature lives or dies on
 *
 * The first run of this command on a real production database finds a decade of hand-made objects.
 * A gate that turns red there is not adopted, it is switched off — and a command nobody runs reports
 * nothing at all. So the default prints everything and exits clean, and blocking is reached only by
 * asking for it: `--fail-on-drift`, or `deploy.drift.mode = gate` written down once, deliberately.
 *
 * That green exit code is only defensible because **the mode is printed with the findings**. Without
 * that line a reader would see zero and believe it meant no drift, which is the exact silent green
 * this package refuses everywhere else.
 *
 * ## Where the two sides come from
 *
 * The LIVE side is the catalog of the database named on the command line, read through the sealed
 * read-only session — this command never writes to it.
 *
 * The EXPECTATION side is a **replay**: the migration state applied for real into a throwaway
 * database, whose catalog is then read with the SAME request. That half creates and drops a
 * database, so it runs behind the production guard and nowhere else.
 *
 * ## It carries NO time budget, unlike both deploy commands
 *
 * `sqlens:predeploy` and `sqlens:postdeploy` hold themselves to a configured number of milliseconds
 * and report a finding when they break it. This command has no such number, and the omission is a
 * decision rather than a gap somebody forgot to fill.
 *
 * Any figure written here would be invented. The expectation side is a real replay of the migration
 * history into a throwaway database, so the run is dominated by how much history a project has — 40
 * migrations and 4,000 are not the same measurement, and neither number is about this package. An
 * invented budget goes red on projects behaving perfectly, and the first fix anybody reaches for is
 * to delete the check.
 *
 * What replaces it is a statement about where this command belongs: NOT in a deploy script's hot
 * path, but in a CI or cron-adjacent run outside the deploy window, where taking a minute costs
 * nobody anything. A team that wants the comparison inside a deploy has
 * `sqlens:postdeploy --expect-shadow` — which is off by default, behind the production guard, and
 * deliberately outside THAT command's budget for the same reason.
 */
final class DriftCommand extends Command
{
    protected $signature = 'sqlens:drift
        {--connection= : The connection to compare; the application default when omitted}
        {--format= : The report format — console, json, github, sarif, or agent (defaults to the configured format)}
        {--fail-on-drift : Exit non-zero when the two sides disagree — off unless named}
        {--allow-undetermined : Exit clean when the ONLY thing blocking is what could not be read}
        {--exclude-file= : The differences this project has accepted; the configured path when omitted}
        {--update-excludes : Write every difference this run found into the exclude file, each needing a reason}
        {--force : Skip the confirmation the production guard asks for}';

    protected $description = 'Compare the live schema against a replay of the migration state.';

    /** Beside `composer.json`, like the debt ledger — a decision log, not configuration. */
    public function handle(
        DriverCaptorFactory $captors,
        ReaderConnectionFactory $connections,
        CatalogReaderFactory $readers,
        PendingResolver $pending,
        ShadowClearance $clearance,
        ReporterManager $reporters,
        ConfigRunContextCollector $runContext,
        Repository $config,
        Application $app,
    ): int {
        $connectionName = $this->connectionName($config);

        // FIRST, before anything reaches a database — and earlier than the sibling deploy commands
        // resolve theirs, deliberately. The expectation side of this comparison CREATES and drops a
        // database; discovering a typo in `--format` after that work would spend a provision, a
        // full migration replay and a teardown to produce an error message that was available
        // before any of it started.
        //
        // Refused, never fallen back from. A quiet fall back to console succeeds, emits the wrong
        // shape, and leaves whatever was parsing it with nothing.
        try {
            $reporter = $reporters->reporter(is_string($format = $this->option('format')) ? $format : null);
        } catch (UnknownReporterFormat $error) {
            $this->outputErrorLine($error->getMessage());

            return ExitCode::Misconfiguration->value;
        }

        $builder = $captors->shadowReference($connectionName, $connections, $readers);

        if (! $builder instanceof ShadowReferenceBuilder) {
            $this->outputErrorLine('sqlens:drift: '.$builder->reason->value);

            return ExitCode::Misconfiguration->value;
        }

        // Through the CONTRACT, and the container binding is what assembles it. Building it here
        // would mean importing Illuminate\Database into the console layer, which the core-purity
        // guard forbids and rightly: a command that holds a database class has a second way to
        // reach a database beside the sealed reader, and "this command only reads" stops being
        // something the architecture can prove.
        $resolution = $pending->resolve($connectionName);

        // Narrowed on the property for the same reason as the snapshot below: `isResolved()` is the
        // readable way to ask, and a method call cannot narrow a nullable — the reason would then be
        // `?PendingSkipReason` in the very branch that exists because there IS one.
        if ($resolution->skip instanceof PendingSkipReason) {
            // A migration set that could not be enumerated is not an empty one, and treating it as
            // empty would make the expectation side "the database as provisioned" — against which
            // every object the migrations added reads as unexpected drift. Hundreds of findings, all
            // of them artefacts.
            $this->outputErrorLine('sqlens:drift: the pending migrations could not be resolved: '
                .($resolution->skip->value));

            return ExitCode::Misconfiguration->value;
        }

        $mode = DriftRunMode::resolve(
            $this->option('fail-on-drift') === true,
            $config->get('sqlens.deploy.drift.mode'),
        );

        $excludePath = $this->excludePath($config, $app);
        $request = $this->request($config);
        // Named arguments, and the reason is a defect this line shipped with: the positional form
        // read `new SubjectContext($connectionName, …)`, and `SubjectContext`'s first parameter is
        // the DRIVER. Every run therefore asked the catalog factory for a reader named after the
        // connection — which happens to work on a project whose connection is called `pgsql` and
        // fails on every other one with "no catalog readers are registered for the … driver".
        // Found by the first test that ran this command against a real database.
        $context = new SubjectContext(
            driver: $this->driver($config, $connectionName),
            profile: $this->profile($config),
            strictTools: false,
        );

        // The reader is held rather than used and dropped, because the run has to be able to say
        // what it compared. `CatalogRequest`'s empty `types` filter means "every type this reader
        // supports", and which types those are is a property of the DRIVER — nine on PostgreSQL, six
        // on MySQL. Without it a `"entries": []` says "nothing differs" when it means "nothing
        // differs among whatever this build happens to look at".
        $catalogReaders = $readers
            ->for($context->driver, $connections->forConnection($connectionName), $connections->budget(), $context);

        // Through the SHARED comparison, which `sqlens:postdeploy --expect-shadow` also calls. Two
        // commands answering "does this database match its migrations" from two code paths would be
        // free to disagree, and would the first time somebody fixed a normalization in one of them.
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
            $catalogReaders->catalog,
        );

        $reference = $comparison->reference;

        // No expectation, no comparison — and NOT an empty one. A run that could not build the
        // reference has established nothing about the live database, so it reports the named reason
        // and returns the undetermined code rather than a reassuring zero.
        // Narrowed on the PROPERTY rather than through `isComplete()`, and that is not a style
        // choice: a method call cannot narrow a nullable, so `$report` below would be `?DriftReport`
        // and every use of it would take a null the type system had already been told could not
        // arrive. Reading the property keeps the invariant in the types.
        $report = $comparison->report;

        if (! $report instanceof DriftReport) {
            $this->outputErrorLine('mode: '.$mode->value);
            $this->outputErrorLine('sqlens:drift: no expectation could be built: '.$reference?->reason?->value);

            return $this->option('allow-undetermined') === true && $mode === DriftRunMode::Gate
                ? ExitCode::Clean->value
                : ExitCode::UndeterminedInStrictMode->value;
        }

        // `--update-excludes` is HOUSEKEEPING and ends the run — it does not also report.
        //
        // Writing the file and then gating on the very differences just written would be a command
        // that can never fail on the run that changed anything, which is the shape of a gate nobody
        // can trust. It writes, says what it wrote, and exits clean; the next ordinary run is the
        // one that judges.
        if ($this->option('update-excludes') === true) {
            return $this->writeExcludes($excludePath, $report);
        }

        try {
            $outcome = DriftExcludes::from(DriftExcludeFile::read($excludePath))->applyTo($report);
        } catch (UnreadableDriftExcludes $refusal) {
            $this->outputErrorLine($refusal->getMessage());

            return ExitCode::Misconfiguration->value;
        }

        // Reported BEFORE the findings, and as a failure rather than a note. An entry that covers
        // nothing is how an exclude file rots: it keeps looking like a decision while protecting
        // nothing, and forty of them are indistinguishable from four that are still true.
        if ($outcome->stale !== []) {
            $this->outputErrorLine(UnreadableDriftExcludes::staleEntries(
                $excludePath,
                array_map(static fn (DriftExcludeEntry $entry): string => $entry->describe(), $outcome->stale),
            )->getMessage());

            return ExitCode::Misconfiguration->value;
        }

        $report = $outcome->report;

        $hatchOpen = $this->option('allow-undetermined') === true;

        $this->renderSummary(
            $mode,
            $report->counts(),
            count($report->blindSpots),
            $outcome->excluded,
            $catalogReaders->catalog->readableObjectTypes(),
        );

        // Through the SAME reporters everything else uses, carrying findings as findings. A drift
        // verdict is not a new kind of thing — it is the same three-valued statement about a
        // database that `lint` and `audit` produce — and a private shape would have cost it the
        // severity axis, `downtime_class`, the baseline, suppression and every format but prose.
        $reporter->report(
            Result::of(DriftFindings::of($report, $context, $connectionName), new RunMetadata(
                serverVersions: [],
                toolVersions: [],
                // The expectation side is a real replay into a throwaway database, which is what
                // `shadow` means. Saying `static` would claim this run reasoned from migration text
                // it never executed.
                mode: CaptureMode::Shadow,
                profile: $context->profile,
                strictTools: false,
            )),
            // BOTH policy facts on the record, because neither is visible in the document otherwise.
            //
            // The mode is printed on STDERR for the person at the console, and that was the whole
            // story until a consumer archived the JSON: a `report` run and a `gate` run over the same
            // drifted database produced byte-identical documents. The exit codes differ; the exit
            // code is not what gets kept.
            //
            // The waiver has its own reason and it is worse: `DriftExitPolicy::waived()` was written
            // and fully tested for exactly this line and then never called, so a run the hatch let
            // through was indistinguishable from one that found nothing — the case the field's own
            // docblock calls "precisely the silent green this gate exists to refuse".
            $runContext->collect()
                ->withDriftMode($mode)
                ->withComparedObjectTypes($catalogReaders->catalog->readableObjectTypes())
                ->withUndeterminedWaiver(DriftExitPolicy::waived(
                    $mode,
                    count($report->entries),
                    count($report->blindSpots),
                    $hatchOpen,
                )),
            $this->getOutput()->getOutput(),
        );

        return DriftExitPolicy::decide(
            $mode,
            count($report->entries),
            count($report->blindSpots),
            $hatchOpen,
        )->value;
    }

    /**
     * The header and the counts, in that order.
     *
     * The mode goes FIRST and unconditionally. A line that appeared only in gate mode would make its
     * absence the claim, and an absent claim is the reading this package refuses.
     *
     * @param  array<string, int>  $counts
     * @param  non-empty-list<SchemaObjectType>  $compared
     */
    private function renderSummary(
        DriftRunMode $mode,
        array $counts,
        int $blindSpots,
        int $excluded,
        array $compared,
    ): void {
        // To STDERR, all of it — this is the run's own commentary and not the report. It used to go
        // to STDOUT, which was harmless while `--format` was ignored and became a defect the moment
        // it was honored: four lines of prose in front of a JSON document leave `jq` with a parse
        // error, and the report the flag exists to produce unreadable.
        $this->outputErrorLine('mode: '.$mode->value);

        foreach (DriftClass::cases() as $class) {
            $this->outputErrorLine($class->value.': '.($counts[$class->value] ?? 0).' — '.$class->description());
        }

        // Printed even at zero, for the same reason the mode is: a reader has to be able to tell
        // "nothing could not be read" from "nobody counted".
        $this->outputErrorLine('undetermined: '.$blindSpots);

        // The withdrawn differences are COUNTED, never merely absent — and that is the whole
        // difference between an exclude file and a blindfold. A report that showed three findings
        // where the comparison found forty would be accurate in every line and misleading as a
        // whole; the reader has to be able to ask what the other thirty-seven were.
        $this->outputErrorLine('excluded: '.$excluded);

        // The scope, LAST and always — the line that tells a reader what the counts above are counts
        // OF. `undetermined` above says what could not be read; this says what was never in the
        // reading, which is a different sentence and the one nobody could get before.
        //
        // Phrased as a closed list plus an explicit "and nothing else", because a bare list invites
        // the reading "these among others". Stored routines are the case that made it necessary: no
        // reader constructs one, so a drift run over an edited procedure found nothing and said so
        // with confidence.
        $types = array_map(static fn (SchemaObjectType $type): string => $type->value, $compared);
        sort($types);

        $this->outputErrorLine('compared: '.implode(', ', $types).' — and nothing else');
    }

    /**
     * Write every difference this run found into the exclude file, and say what happened.
     *
     * Merged rather than overwritten: an existing entry keeps the reason somebody wrote for it, so
     * running this twice cannot replace a real explanation with the placeholder. That also makes the
     * command idempotent on an unchanged database — the second run writes the same bytes.
     */
    private function writeExcludes(string $path, DriftReport $report): int
    {
        try {
            $file = DriftExcludeFile::read($path)->with(DriftExcludes::proposalsFor($report));
        } catch (UnreadableDriftExcludes $refusal) {
            // A file that could not be read is not one to overwrite. Doing so would turn a typo into
            // the deletion of every decision the project had recorded.
            $this->outputErrorLine($refusal->getMessage());

            return ExitCode::Misconfiguration->value;
        }

        $directory = dirname($path);

        if (! is_dir($directory) && ! @mkdir($directory, 0o755, true) && ! is_dir($directory)) {
            $this->outputErrorLine('sqlens:drift: the directory for '.$path.' could not be created.');

            return ExitCode::Misconfiguration->value;
        }

        if (@file_put_contents($path, $file->contents()) === false) {
            $this->outputErrorLine('sqlens:drift: '.$path.' could not be written.');

            return ExitCode::Misconfiguration->value;
        }

        $this->outputErrorLine('excludes written: '.count($file->entries).' entr'.(count($file->entries) === 1 ? 'y' : 'ies').' in '.$path);
        $this->outputErrorLine('Every new entry carries a placeholder reason, and the next run REFUSES it. Replace each one with why the difference is deliberate, or delete the entry.');

        return ExitCode::Clean->value;
    }

    /**
     * Where the accepted differences are recorded.
     *
     * The flag wins over the config, and the config over the shipped default. The default sits in
     * the project root beside `composer.json` rather than under `config/`, because it is a decision
     * log rather than configuration — the same reason the debt ledger lives where it does.
     *
     * The CONFIG value is repository-relative and the FLAG is taken as given, which is the same
     * split `deploy.debt.path` makes. A configured absolute path would put a decision log outside
     * the repository, where its changes are reviewed by nobody; a flag is a one-run override typed
     * by a person who can see where they are pointing.
     */
    private function excludePath(Repository $config, Application $app): string
    {
        $named = $this->option('exclude-file');

        if (is_string($named) && $named !== '') {
            return $named;
        }

        $configured = $config->get('sqlens.deploy.drift.exclude_file');

        return DriftExcludeFile::configuredPath(is_string($configured) ? $configured : null, $app->basePath());
    }

    private function connectionName(Repository $config): string
    {
        $named = $this->option('connection');

        if (is_string($named) && $named !== '') {
            return $named;
        }

        $default = $config->get('database.default');

        return is_string($default) ? $default : '';
    }

    private function request(Repository $config): CatalogRequest
    {
        $schemas = $config->get('sqlens.catalog.schemas');

        return new CatalogRequest(
            schemas: is_array($schemas) ? array_values(array_filter($schemas, is_string(...))) : [],
        );
    }

    /**
     * The engine behind a connection NAME, from the same key every other command reads it from.
     *
     * Empty rather than guessed when the connection is not configured: the catalog factory refuses
     * an unknown driver by name, which is a better message than one invented here would be.
     */
    private function driver(Repository $config, string $connectionName): string
    {
        $driver = $config->get('database.connections.'.$connectionName.'.driver');

        return is_string($driver) ? $driver : '';
    }

    private function profile(Repository $config): string
    {
        $profile = $config->get('sqlens.profile');

        return is_string($profile) ? $profile : 'ci';
    }

    private function outputErrorLine(string $message): void
    {
        $output = $this->getOutput()->getOutput();

        ($output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output)->writeln($message);
    }
}
