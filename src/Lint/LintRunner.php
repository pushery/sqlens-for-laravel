<?php

declare(strict_types=1);

namespace Pushery\SQLens\Lint;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Filesystem\Filesystem;
use LogicException;
use Pushery\SQLens\Canonical\Extensions\CanonicalExtensionRegistry;
use Pushery\SQLens\Canonical\Fingerprint;
use Pushery\SQLens\Capture\CaptureConnectionResolver;
use Pushery\SQLens\Capture\CaptureFindingCatalog;
use Pushery\SQLens\Capture\CaptureFindingCollector;
use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\MigrationPaths;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Capture\PendingMigrationResolver;
use Pushery\SQLens\Capture\PendingResolution;
use Pushery\SQLens\Capture\PendingSkipReason;
use Pushery\SQLens\Capture\SessionGuard;
use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Capture\SingleFileFailure;
use Pushery\SQLens\Capture\SingleFileResolver;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Categories\CategoryFilter;
use Pushery\SQLens\Categories\CategorySelection;
use Pushery\SQLens\Config\ConfigViolation;
use Pushery\SQLens\Console\ExitCode;
use Pushery\SQLens\Console\ExitCodeResolver;
use Pushery\SQLens\Contracts\Captor;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Contracts\StatisticsDependent;
use Pushery\SQLens\Deploy\DebtContext;
use Pushery\SQLens\Deploy\DebtEntry;
use Pushery\SQLens\Deploy\DebtLedger;
use Pushery\SQLens\Deploy\DebtLedgerRefusal;
use Pushery\SQLens\Deploy\DebtMode;
use Pushery\SQLens\Deploy\DebtOrigin;
use Pushery\SQLens\Deploy\DebtReconciliation;
use Pushery\SQLens\Deploy\DebtRegistrar;
use Pushery\SQLens\Deploy\DebtState;
use Pushery\SQLens\Drivers\Capture\DriverCaptorFactory;
use Pushery\SQLens\Drivers\DriverManager;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\DriverResolutionReason;
use Pushery\SQLens\Drivers\EngineIdentity;
use Pushery\SQLens\Drivers\ServerVersionFloor;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Engine\ServerVersionResolver;
use Pushery\SQLens\Exceptions\UnreadableBaseline;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\RunMetadata;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Levels\LevelGate;
use Pushery\SQLens\Reporting\Baseline\BaselineEntry;
use Pushery\SQLens\Reporting\Baseline\BaselineFile;
use Pushery\SQLens\Reporting\Baseline\BaselineRuleIds;
use Pushery\SQLens\Reporting\Baseline\ConfiguredBaseline;
use Pushery\SQLens\Reporting\Baseline\FindingFingerprint;
use Pushery\SQLens\Reporting\Baseline\StaleBaselinePolicy;
use Pushery\SQLens\Reporting\CaptureMode as ReportingCaptureMode;
use Pushery\SQLens\Reporting\ConfigRunContextCollector;
use Pushery\SQLens\Reporting\ReportedServerVersion;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\Suppression\SuppressionCandidate;
use Pushery\SQLens\Reporting\Suppression\SuppressionResolver;
use Pushery\SQLens\Reporting\VersionSource;
use Pushery\SQLens\Rules\RuleRegistry;
use Pushery\SQLens\Rules\StabilityGate;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Rules\VersionRuleGate;
use Pushery\SQLens\ServerVersion;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\SubjectContext;
use Pushery\SQLens\Tools\MissingToolNotice;
use Pushery\SQLens\Tools\Squawk\SquawkContribution;
use Pushery\SQLens\Tools\Squawk\SquawkTool;
use Pushery\SQLens\Tools\ToolDiagnostic;
use Pushery\SQLens\Tools\ToolLocator;
use Pushery\SQLens\Tools\UnverifiableToolPrefixes;
use Throwable;

/**
 * The lint suite's spine: it drives one run from a connection and a set of migration
 * paths to a three-valued result, a reproducibility header, and an exit code — the
 * whole pipeline (pending resolution → capture → canonicalization → rules → findings)
 * wired into ONE pass, so the console command stays a thin translation of options in
 * and a report out.
 *
 * It refuses to guess and it never greens silently: an unsupported engine stops the
 * run with a named failure and the misconfiguration exit (not a finding, because
 * nothing was linted), an unresolvable pending set becomes a single `LINT.SKIPPED.*`
 * undetermined finding (never an empty pass read as clean), and every migration the
 * capture could not conclude leaves an undetermined finding that colors the verdict.
 *
 * It knows no concrete driver — the captor and the driver's rules arrive through the
 * factory and the driver contract — so the console layer stays driver-free.
 */
final readonly class LintRunner implements LintRuns
{
    public function __construct(
        private Application $app,
        private DriverManager $drivers,
        private DriverCaptorFactory $captors,
        private DatabaseManager $database,
        private Migrator $migrator,
        private ServerVersion $versions,
        private ServerVersionResolver $versionResolver,
        private ConfigRunContextCollector $contextCollector,
        private ExitCodeResolver $exitCodes,
        private Repository $config,
        private ToolLocator $toolLocator,
        private SquawkContribution $squawk,
        private CanonicalExtensionRegistry $extensions,
    ) {}

    /**
     * Run the lint suite over a connection, or the resolved default, capturing the
     * pending migrations found under the given paths. A null path list means "the
     * application's registered migration paths" — the console layer cannot name a
     * database class to discover them, so that resolution lives here.
     *
     * @param  list<string>|null  $migrationPaths
     * @param  list<string>|null  $categories  category values to scope to (null = the config's, empty = all)
     * @param  bool  $applyBaseline  whether to suppress against the configured baseline; the baseline command turns this OFF, because it is WRITING that baseline and must see every finding, not the ones the previous baseline already accepted (config and annotation suppression still apply — those findings are handled by other means and need no baselining)
     * @param  bool|null  $includeVendorMigrations  whether a migration discovered inside `vendor/` is enumerated. Null reads `sqlens.security.include_vendor_migrations`, which is what every ordinary caller wants. `sqlens:predeploy` passes TRUE and does not read the config, because a package's migration really does run during a deploy and really can take a lock — see PreflightService for that reasoning. A caller that NAMED its paths gets them unfiltered regardless.
     */
    public function run(?string $connection, ?array $migrationPaths, CaptureMode $mode, ?string $assumeServerVersion = null, ?int $level = null, ?array $categories = null, bool $applyBaseline = true, ?bool $strictTools = null, ?string $file = null, ?GuardDecision $guard = null, bool $roundtrip = false, ?DebtMode $debt = null, ?bool $includeVendorMigrations = null): LintOutcome
    {
        // The session bound belongs to the RUN, not to the connection — and the connection
        // is the HOST APPLICATION's, which under Octane, a queue worker or a test suite
        // outlives this call. Every exit from the run below goes through this finally, so a
        // skip, an unsupported engine and a thrown error all put the session back. Leaving
        // the bound behind would make an unrelated query fail later for a reason the
        // application never chose: harm from the mechanism that exists to prevent harm.
        // Carried by reference rather than on a property: this class is readonly, and that
        // is worth keeping — a runner that accumulated state between runs is a different
        // and worse thing than one that hands its cleanup back out.
        $release = null;

        try {
            return $this->runBounded($release, $connection, $migrationPaths, $mode, $assumeServerVersion, $level, $categories, $applyBaseline, $strictTools, $file, $guard, $roundtrip, $debt, $includeVendorMigrations);
        } finally {
            if ($release instanceof Closure) {
                $release();
            }
        }
    }

    /**
     * The run itself. Private because the session bound above must not be bypassable: a
     * caller that reached this directly would leave the host connection altered.
     *
     * @param  Closure|null  $release  set to the session restorer once one is owed
     * @param  list<string>|null  $migrationPaths
     * @param  list<string>|null  $categories
     */
    private function runBounded(?Closure &$release, ?string $connection, ?array $migrationPaths, CaptureMode $mode, ?string $assumeServerVersion = null, ?int $level = null, ?array $categories = null, bool $applyBaseline = true, ?bool $strictTools = null, ?string $file = null, ?GuardDecision $guard = null, bool $roundtrip = false, ?DebtMode $debt = null, ?bool $includeVendorMigrations = null): LintOutcome
    {
        $connectionName = $this->connectionName($connection);
        // Whether somebody NAMED these paths, decided before the coalesce below overwrites the
        // evidence. `--path` and `sqlens.migration_paths` are a person saying "these", and a run
        // that silently dropped part of what they named would make the argument advisory. Only
        // paths the run discovered on its own can be filtered.
        $pathsWereNamed = $migrationPaths !== null || $this->configuredMigrationPaths() !== null;

        // Path resolution: the --path flag (a non-null argument) wins; else the
        // configured `migration_paths` when a project set them; else the application's
        // registered paths. One precedence, no value threaded twice.
        $migrationPaths ??= $this->configuredMigrationPaths() ?? $this->defaultMigrationPaths();

        // Null means "read the config"; a caller that passes a bool has a reason and carries it
        // (PreflightService does). Named paths win over both — see above.
        $includeVendorMigrations = $pathsWereNamed || ($includeVendorMigrations
            ?? $this->config->get('sqlens.security.include_vendor_migrations') === true);

        // ────────────────────────────────────────────────────────────────────────────────────
        // The connect the run ALREADY makes, moved above the one banner read instead of 180 lines
        // below it.
        //
        // The banner is still acquired exactly once and threaded from here — that has not changed
        // and must not. What changed is that it now reads a handle that EXISTS. Laravel's
        // connection is lazy, so on a freshly started process nothing had opened it yet and this
        // read returned null every time: on MySQL that made `EngineIdentity` refuse the run
        // outright ("Nothing was checked"), correctly, because a `mysql` driver key really can be
        // a MariaDB and a null banner really is no proof. Measured against a reachable MySQL 8.4
        // whose connection answers 8.4.10 from a query one line later.
        //
        // This is NOT a new connection. `boundSourceSession()` opened exactly this one, on exactly
        // this branch, unconditionally — it has moved, not appeared. And it moved EARLIER, so the
        // session budget is applied from a sooner point rather than a later one.
        //
        // It also closes the handle-replacement window structurally. The old comment below warned
        // that forcing the connection open between the read and the check could REPLACE the PDO,
        // so a second read would answer where the first did not; the answer at the time was to
        // freeze the FIRST (null) value and let the check use it. That is backwards — the stale
        // header was the defect, not the more accurate check — and it is what produced this bug.
        // With the force now happening BEFORE the only read, there is no interval left in which
        // two reads could disagree.
        //
        // Three guards on it, and each one is load-bearing:
        //
        //  - `$file === null`: the single-file fast path returns before any of this and must stay
        //    connectionless. `tests/Feature/Lint/FastPathNoDatabaseTest.php` counts ATTEMPTS with a
        //    spy, so a regression here is red rather than quiet.
        //  - a driver this build supports: opening a `sqlite` connection CREATES THE FILE, and
        //    sqlite is a reserved non-goal engine that is refused a few lines below anyway. Read
        //    from the configuration, which needs no connection to answer.
        //  - a failed connect is swallowed: an unreachable server is named by the pending
        //    resolver as `ConnectionUnreachable`, which is the specific and actionable answer.
        //    Crashing here would replace it with a stack trace.
        $connected = $file === null && $this->openSource($connectionName);

        // The server version is resolved once — flag → config → detected → undetermined —
        // and drives both the header (which version, from where) and rule activation.
        // Acquired ONCE, here, and threaded from here on — never read a second time inside the
        // findings block.
        //
        // BETWEEN the open above and this line there is deliberately nothing. The session bounding
        // that used to sit here comes AFTER, and the order is not cosmetic: `SessionGuard` runs
        // statements, and a statement can make Laravel RECONNECT — replacing the handle and with it
        // the banner. Measured while building this change: with the bounding in between, a test
        // that injects a MariaDB banner through `setPdo()` had it silently swapped for the real
        // 8.4.10, and three arms that exist to prove the MariaDB fence went green over a fence that
        // was no longer being tested. The old comment further down warned about exactly this
        // replacement; it was right about the mechanism and applied it at the wrong end.
        $banner = $this->detectedBanner($connectionName);

        if ($connected) {
            // Bound the SOURCE session now — still long before the pending resolution issues its
            // first catalog query. A lint run may point at a production connection, and an
            // unbounded catalog read can sit behind a lock indefinitely, which is the exact harm
            // "primum non nocere" forbids.
            $release = $this->boundSourceSession($connectionName);
        }
        $resolvedVersion = $this->resolveVersion($connectionName, $assumeServerVersion, $banner);
        $activeLevel = $this->resolveLevel($level);
        $selectedCategories = $this->resolveCategories($categories);
        $categoryFilter = new CategoryFilter($selectedCategories);
        $activeCategories = array_map(static fn (Category $category): string => $category->value, $selectedCategories);

        $strict = $this->resolveStrictTools($strictTools);

        // BEFORE the engine is resolved, and that placement is the whole point. An id in a baseline
        // that names no rule suppresses nothing while looking set, and — unlike an ignore list — it
        // cannot be noticed from the output: an entry matching nothing produces exactly what a
        // matching entry produces once the code is fixed. The audit half has refused this since the
        // check was written; the lint half did not, and both halves reading the same file made the
        // difference invisible.
        //
        // Placed here rather than behind the driver because a broken baseline is a fact about the
        // PROJECT's own files, true whatever engine the connection points at — and because a check
        // that sits behind an engine refusal is a check no test on an unsupported engine can reach,
        // which is exactly how the previous attempt at this ended up vacuous.
        $configViolations = $applyBaseline ? $this->baselineViolations() : [];

        if ($configViolations !== []) {
            $configured = $this->config->get("database.connections.{$connectionName}.driver");

            return $this->refusedConfig(
                $configViolations,
                $this->buildContext($connectionName, $mode, $resolvedVersion, $activeLevel, 0, 0, $activeCategories, [], $strict, $roundtrip, guard: $guard),
                $mode,
                $connectionName,
                is_string($configured) && $configured !== '' ? $configured : 'unknown',
                $strict,
                $resolvedVersion,
            );
        }

        // An unsupported engine is a named stop before anything is captured — the
        // misconfiguration exit, and a message rather than per-migration noise.
        $driver = $this->drivers->resolve($connectionName);

        if ($driver instanceof DriverResolutionFailure) {
            // No tool versions in this header, and not for lack of asking: an engine SQLens does
            // not support has no tool with jurisdiction over it, so there is nothing to name.
            return $this->unsupported($driver, $this->buildContext($connectionName, $mode, $resolvedVersion, $activeLevel, 0, 0, $activeCategories, [], $strict, $roundtrip, guard: $guard), $mode, $connectionName);
        }

        // The external tools, diagnosed once and only those with jurisdiction over THIS driver:
        // an available tool's version reaches the header, a missing one becomes a named result
        // (never a silent loss of rules), and — when the run is strict — a fixable absence fails
        // it. A tool that could never have spoken here is absent from all three, because naming
        // it would state a loss the project does not have and, under a strict profile, fail its
        // build for an install that could not have helped.
        //
        // Diagnosed AFTER the driver is known, therefore: reading it earlier would have meant
        // filtering later, at each of the three consumers, and two of them would eventually be
        // one consumer too few.
        $diagnostics = $this->toolLocator->diagnoseFor($driver->key());
        $toolVersions = $this->toolVersions($diagnostics);

        // The supported-version floor, decided ONCE — late enough that the driver, which
        // declares the floor, is known; early enough to reach both the run header above the
        // findings and the notice among them.
        //
        // Not a refusal and not a misconfiguration. A qualified report is worth more than no
        // report, and the misconfiguration path skips the reporter entirely — refusing here
        // would take the findings away from precisely the users least able to judge them for
        // themselves.
        $floorFailure = $this->floorFailure($driver, $resolvedVersion, $banner, $this->configuredPin($assumeServerVersion));

        // The filter axes, in a deterministic order: the level gate first, then the
        // category filter over what level admitted, then the stability gate over what
        // category kept, then the version gate. The active/hidden counts and the active
        // categories reach the header — a level-hidden rule is counted, never a silent pass.
        $gate = new LevelGate(Level::from($activeLevel));
        // Filtered to the LINT suite, symmetrically to what the audit runner does with its own.
        // Without this the registry carries every rule the driver ships, and an audit-only rule
        // then reaches the version gate here: the first one with a version window turned up in a
        // lint run as a version-undetermined finding about a rule that could never have produced
        // a verdict from migration text. It also over-counted `active_rules` in the header by
        // every audit rule, so a lint report claimed to have applied checks it never asked.
        // `rules()` is an iterable, so it is materialized before filtering rather than assumed to
        // be an array — a driver may yield them.
        $registry = RuleRegistry::fromRules(array_values(array_filter(
            [...$driver->rules()],
            static fn (Rule $rule): bool => in_array(Suite::Lint, $rule->suites(), true),
        )));

        // The maturity axis, and the only one whose EMPTY default is the strict reading:
        // an unconfigured stability list admits stable rules only. That is the versioning
        // promise made operative — without it, a rule added in a minor starts failing a
        // pipeline over code nobody touched, which is a breaking change wearing a patch
        // number.
        $stabilityGate = StabilityGate::fromConfig($this->config->get('sqlens.stability'));
        $leveledAndScoped = $stabilityGate->apply($categoryFilter->apply($gate->active($registry)));

        // The version axis, last and three-valued: a rule outside a KNOWN version's
        // window produces no finding; under an UNKNOWN version a version-independent rule
        // still runs, while a version-dependent one becomes an undetermined finding
        // (emitted below) — never a silent skip and never a guess against a default.
        $versionGate = new VersionRuleGate($resolvedVersion->version);
        $activeRules = $versionGate->active($leveledAndScoped);
        $versionUndeterminedRules = $versionGate->undetermined($leveledAndScoped);

        // The statistics axis (use_statistics): a rule that reasons about the server's
        // table statistics cannot conclude from the migration text alone. With
        // statistics on but no reader in this build, it is a named undetermined; with
        // statistics off, it does not run at all. Either way it is pulled out of the set
        // the collector evaluates — a rule that needs a reading it cannot get must never
        // silently pass. Both are separate from the active count, exactly like the
        // version-undetermined rules.
        $useStatistics = $this->config->get('sqlens.use_statistics') === true;
        $statisticsUndeterminedRules = $useStatistics
            ? array_values(array_filter($activeRules, static fn (Rule $rule): bool => $rule instanceof StatisticsDependent))
            : [];
        $activeRules = array_values(array_filter($activeRules, static fn (Rule $rule): bool => ! $rule instanceof StatisticsDependent));

        // Hidden is EVERYTHING this run did not apply, not only what the level gate held back.
        //
        // It used to be `count($gate->hidden($registry))`, which counts one of the four axes. A run
        // narrowed by `--category`, or one whose rules fell outside the server's version window,
        // reported those rules as neither active nor hidden — so `active-rules=7 hidden-rules=0`
        // appeared over a registry of 40, and the header's own purpose (how much of the rule set
        // this run actually applied) was answered wrongly by a number that looked precise.
        //
        // Defined as total-minus-active so the two suites cannot drift: the audit says the same
        // thing with the same arithmetic, and `active + hidden == registered` is an invariant a
        // test can hold both of them to. WHY each rule is missing is not lost — the version gate
        // and the statistics axis each report their own named undetermined finding.
        $context = $this->buildContext($connectionName, $mode, $resolvedVersion, $activeLevel, count($activeRules), count($registry->all()) - count($activeRules), $activeCategories, $toolVersions, $strict, $roundtrip, $floorFailure, $guard);

        // The resolved version rides into the rule context — the detected version or the
        // pin alike, or a named "could not determine". A rule branches only on the version
        // itself, never on its source, so a pin and a live read produce the same verdict
        // (the determinism the pin exists to guarantee); the source travels only so a
        // version-windowed data source can report the run's OWN reason for having none.
        $subjectContext = $this->captors->subjectContextFor($driver->key())->withResolvedServerVersion($resolvedVersion);

        // Strict tool mode: a tool the platform can run but that is not installed fails
        // the run BEFORE any capture — a green CI without it would just be a run with
        // fewer rules. The missing tools are still named as findings, and the exit is
        // the misconfiguration code. A platform with no build for the tool never trips
        // this (it is a documented degradation, not a fixable absence).
        if ($strict && $this->hasStrictFailure($diagnostics)) {
            return $this->strictToolStop($diagnostics, $connectionName, $subjectContext, $context, $mode);
        }

        // The mode decides the SOURCE of the SQL and nothing else: pretend collects it
        // without executing, shadow executes for real against a throwaway database.
        // Everything after this point — canonicalization, rules, gates, suppression,
        // the reporter — is the same code either way.
        $captor = $mode === CaptureMode::Shadow && $guard instanceof GuardDecision
            ? $this->captors->shadow($connectionName, $guard, $roundtrip)
            : $this->captors->pretend($connectionName);

        // A driver the manager supports but the factory has no capture wiring for
        // (a registered third-party without a formatter) is the same named stop.
        if (! $captor instanceof Captor) {
            return $this->unsupported($captor, $context, $mode, $connectionName);
        }

        // The subject source is the ONLY thing the fast path changes: a single --file
        // migration instead of the pending set. A file that does not resolve to a
        // migration is a named misconfiguration, never a silent empty run.
        if ($file !== null) {
            $single = $this->resolveSingleFile($file, $migrationPaths, $connectionName);

            if ($single instanceof SingleFileFailure) {
                return $this->fileMisconfiguration($single, $context, $mode, $connectionName);
            }

            $resolution = PendingResolution::resolved([$single]);
        } else {
            // The source session was opened and bounded at the top of this method ,
            // before the banner read that needs the handle. It used to happen here, and here was
            // 180 lines too late for the one value that depends on it.

            // The FIRST point at which the engine can be identified, and the last one before any
            // rule reasons about it. Laravel's connection is lazy, so every earlier anchor sees
            // no banner at all — one of them was tried, and it would have refused the run for
            // every healthy MySQL user, from the check meant to protect them.
            //
            // A refusal here is deliberate and is not a new decision: the shipped message in all
            // seven locales already says "Nothing was checked", which is only true if nothing
            // runs. MariaDB answers Laravel's `mysql` driver without sharing MySQL 8.4 semantics,
            // so every rule below would produce advice that is confident, specific and about the
            // wrong product. Still before `resolvePending()`'s first catalog query, before the
            // capture, and before any shadow database is created.
            // The banner acquired at the TOP, threaded — never read a second time here.
            //
            // This called `detectedBanner()` again and it was wrong, measurably: between that
            // first read and this line the run forces the connection open, and forcing it can
            // REPLACE the handle. The header then reported one server and this check judged
            // another, out of one run. Proven with a connection whose PDO reported a MariaDB
            // banner: the header showed 5.5.5 and the check saw the real 8.4.10, so it refused
            // nothing and a MariaDB user would have received a full report of MySQL verdicts.
            //
            // The rule is already written three hundred lines above, for the floor. It applies
            // here for the same reason and was broken by the later wiring.
            // Only when a connection was really opened. Without one there is no evidence about the
            // engine at all, and "we could not reach the server" is both more specific and more
            // actionable than "we could not confirm the driver" — the pending resolver names it as
            // `ConnectionUnreachable`, so the absence is still reported, once, by its own name.
            $engine = $connected ? new EngineIdentity()->check($driver, $banner) : null;

            if ($engine instanceof DriverResolutionFailure) {
                // No release here. `run()` restores in a `finally` around this whole call, so
                // doing it again would restore the same snapshot twice — harmless today and only
                // because `SessionGuard::restore()` happens to be idempotent, which is not a
                // property this path should be relying on. The type checker found it the moment
                // `$release` stopped being nullable at this point.
                return $this->unsupported($engine, $context, $mode, $connectionName);
            }

            $resolution = $this->resolvePending($connectionName, $migrationPaths, $includeVendorMigrations);

            if (! $resolution->isResolved()) {
                return $this->skipped($resolution, $connectionName, $migrationPaths, $subjectContext, $context, $mode);
            }
        }

        // The DENOMINATOR, attached before anything is judged. Every count the report prints is a
        // numerator, and a numerator alone cannot separate "nothing was wrong" from "almost nothing
        // was read" — the state a consuming project met when `--path=database/migrations` read one
        // directory level (Laravel's own `getMigrationFiles()` globs `*_*.php`, not a tree) and
        // reported a clean run over 32 of 330 migrations.
        //
        // It is the resolved set rather than the discovered one, so it is the number of migrations
        // this run actually judged. Both the `--file` fast path and the pending path arrive here,
        // and each states its own.
        $context = $context->withSubjectCount(count($resolution->migrations));

        $run = $captor->capture($resolution->migrations, CaptureSection::Up);

        // Kept for the outcome. Six of this method's seven exits are failure paths with no capture
        // at all, and null is the right answer there rather than a missing one — so only the exit
        // that HAS a run carries these out.
        $pendingFiles = array_map(
            static fn (PendingMigration $migration): string => $migration->file,
            $resolution->migrations,
        );
        // Handed on whole rather than flattened to SQL. A `CapturedStatement` already carries
        // `canonicalSql`, `statementKind` and `targets` — so a caller asking "which tables need an
        // exclusive lock" reads the answer this run produced instead of parsing the SQL again and
        // risking a different one. Flattening here would throw that away and force the second
        // parser this ticket's guardrail forbids.
        $pendingStatements = $run->statements();
        $findings = $this->collector()->collect($run, $activeRules, $subjectContext, $this->projectRoot());

        // A category filter that removed every rule is not a clean run — it checked
        // nothing. Named as undetermined so an accidentally over-narrow scope is
        // visible, never a false green. (The level axis reports its effect through
        // the hidden-rule count instead; this guard is the category filter's.)
        if ($categoryFilter->isActive() && $activeRules === []) {
            $findings[] = $this->noActiveRulesFinding($activeCategories, $connectionName, $subjectContext);
        }

        // A pin that disagreed with the connected server is its own finding — the
        // result reflects the pin, not the live instance, and that drift is reported.
        if ($resolvedVersion->hasSkew()) {
            $findings[] = $this->skewFinding($resolvedVersion, $connectionName, $subjectContext);
        }

        // A pin that could not be read is a configuration fault, and it is reported
        // whether or not any rule happened to need the version. Without this the run
        // simply says "unknown" — the same thing it says when nothing was pinned — so a
        // project could keep believing it audits against a fixed version for as long as
        // nobody reads the header closely.
        if ($resolvedVersion->unreadablePin !== null) {
            $findings[] = $this->unreadablePinFinding($resolvedVersion->unreadablePin, $connectionName, $subjectContext);
        }

        // The floor, decided far above, reported HERE — among the findings, after they were
        // produced. That placement is the whole of the decision: the run continues, says
        // unmistakably what its verdicts are worth, and lets the reader act on them anyway.
        // Refusing instead would take a qualified report away from exactly the readers least
        // able to qualify it themselves.
        if ($floorFailure instanceof DriverResolutionFailure) {
            $findings[] = $this->belowFloorFinding($floorFailure, $resolvedVersion->source, $connectionName, $subjectContext);
        }

        // In the non-strict path a missing tool is not an error but is never silent:
        // each one is a named undetermined finding saying what it would have added, so
        // the run reports "fewer rules ran" instead of quietly running fewer.
        foreach ($diagnostics as $diagnostic) {
            if ($diagnostic->isMissing()) {
                $findings[] = $this->missingToolFinding($diagnostic, $connectionName, $subjectContext);
            }
        }

        // A version-dependent rule under an unknown server version is neither a pass nor
        // a silent skip: it becomes an undetermined finding under the rule's own id,
        // naming that the version could not be determined and pointing at the pin — so a
        // fast-path run reports exactly what it could not check, never quietly drops it.
        foreach ($versionUndeterminedRules as $rule) {
            $findings[] = $this->versionUndeterminedFinding($rule, $resolvedVersion, $connectionName, $subjectContext);
        }

        // A statistics-dependent rule, run with statistics on but no reader available,
        // reports what it could not check under its own id — never a quiet drop.
        foreach ($statisticsUndeterminedRules as $rule) {
            $findings[] = $this->statisticsUnavailableFinding($rule, $connectionName, $subjectContext);
        }

        // What the external tool adds, folded in HERE — after the rules produced their own
        // verdicts and before suppression touches anything.
        //
        // Before suppression because de-duplication has to happen first: a baseline written from
        // findings that were about to be merged would pin the duplicates, and every later run
        // would then carry an entry for a finding that no longer exists in that shape.
        //
        // After the rules because the merge is one-directional. The run's own findings are what
        // they were with the tool and without it; the tool can confirm one and it can add its
        // own, and it can do nothing else. A machine with the binary installed must not gate
        // differently from one without it.
        foreach ($diagnostics as $diagnostic) {
            if ($diagnostic->tool instanceof SquawkTool) {
                $findings = $this->squawk->contribute($findings, $run, $diagnostic, $resolvedVersion, $subjectContext, Level::from($activeLevel), $file !== null);
            }
        }

        // The debt pass runs HERE — after the rules and the tool contribution, before suppression,
        // and after every early return above.
        //
        // After the early returns is not an accident of placement. A run that was SKIPPED (no
        // pending migrations), refused (unsupported engine), or stopped on a missing strict tool
        // produced no findings — so it owes no debts — and reconciling a ledger against an empty
        // set would report every recorded entry as settled. A recording run in that state would
        // then EMPTY the account, on the strength of having looked at nothing. The account is only
        // consulted by a run that actually linted.
        //
        // Before suppression on purpose: a debt finding is a finding. It goes through the same
        // baseline, the same config ignore list, the same gates and the same deterministic order as
        // every other one. A pass that appended after `Result::of()` would have to rebuild that
        // pipeline, the second copy would drift from the first, and both halves would stay green
        // while a suppressed debt finding came through anyway.
        $findings = [...$findings, ...$this->debtFindings($debt, $findings, $registry->all(), $driver->key(), $subjectContext, $file !== null)];

        // The three-stage suppression chain (baseline · config · annotation) is
        // applied here, after the rule engine and before the reporter, so a second
        // run after a baseline shows only NEW findings — and never suppresses one
        // silently: the hidden findings and the stale instructions ride on the Result.
        // Which suppression sources could not be CHECKED this run. An accepted finding from a tool
        // that never answered is not a finding somebody fixed, and reporting it as stale would send
        // a reader to delete a line that comes straight back on the next machine that has the tool.
        $unverifiable = UnverifiableToolPrefixes::from($diagnostics);

        $suppression = $this->suppressionResolver($applyBaseline)->resolve(
            $this->candidates($findings, $run, $subjectContext),
            Suite::Lint,
            $unverifiable,
        );

        // …and each one is NAMED, because "kept in the file" without a word is the same silence as
        // deleting it: nobody learns that this run checked less than the last one.
        //
        // Added to the VISIBLE findings rather than to `$findings`, which the resolver has already
        // read — appending there would have produced notices that never reach the report, which is
        // precisely the shape of defect this notice exists to prevent.
        $visible = $suppression->visible;

        foreach ($suppression->unverifiableBaselineEntries as $entry) {
            $visible[] = $this->unverifiableBaselineFinding($entry, $connectionName, $subjectContext);
        }

        $result = Result::of(
            $visible,
            $this->metadata($mode),
            $suppression->suppressed,
            $suppression->staleBaselineEntries,
            $suppression->unusedIgnoreRules,
        );

        // What a baseline entry that matched nothing COSTS — the project's answer, read from the same
        // key the audit reads and applied through the same policy object, because one file cannot
        // mean two things depending on which command opened it. `report` (the default) names the
        // stale entries and leaves the verdict alone; `error` ends the run as a misconfiguration.
        $staleBreaks = StaleBaselinePolicy::fromConfig($this->config->get('sqlens.baseline.stale'))
            ->breaks($result->staleBaselineEntries);

        return new LintOutcome(
            $result,
            $context,
            $this->exitCodes->resolve($result, $context, $staleBreaks),
            $connectionName,
            pendingFiles: $pendingFiles,
            pendingStatements: $pendingStatements,
        );
    }

    /** The connection a run addresses: an explicit `--connection`, else the resolved default. */
    private function connectionName(?string $connection): string
    {
        if ($connection !== null && $connection !== '') {
            return $connection;
        }

        return $this->drivers->defaultConnectionName();
    }

    /**
     * The application's default migration paths: the framework's `database/migrations`
     * plus any a package registered on the migrator. Read from the migrator here (the
     * lint layer) rather than the console, which must name no database class.
     *
     * @return list<string>
     */
    private function defaultMigrationPaths(): array
    {
        // `databasePath()`, not `basePath('database/migrations')`. They are the same string in a
        // stock application and different the moment one relocates its database directory — and an
        // application that did would have SQLens linting a directory Laravel does not migrate from,
        // reporting clean while never having looked at the migrations that actually run.
        // Delegated to the shared resolver so the lint layer and the capture layer cannot end up
        // with different ideas of what a migration path is.
        return new MigrationPaths($this->app, $this->migrator, $this->config)->all();
    }

    /**
     * Open the source connection, and say whether it opened.
     *
     * Split out of {@see self::boundSourceSession()} so the connect can happen BEFORE the banner
     * read that depends on it  while the bounding still happens immediately after.
     *
     * A reserved engine is never opened. `sqlite` is refused a few lines further down as a non-goal
     * driver — and opening one CREATES THE FILE, so connecting first to learn a version nobody will
     * use would leave a database behind on a run that refuses. The key is read from the
     * configuration, which answers without a connection.
     */
    private function openSource(string $connectionName): bool
    {
        if (in_array($this->driverKey($connectionName), ['mariadb', 'sqlite', 'sqlsrv'], true)) {
            return false;
        }

        try {
            $this->database->connection($connectionName)->getPdo();

            return true;
        } catch (Throwable) {
            // Left for the pending resolver to name: its own check turns this into a
            // `ConnectionUnreachable` skip, which says more than a crash here would.
            return false;
        }
    }

    /**
     * Bound the resolved source connection's own session — statement and lock
     * timeouts — before the first catalog query runs against it. This is the second
     * half of "first, do no harm" on the DEFAULT (pretend) path, which the shadow
     * side already honors on its own connection: a run against a production database
     * must never be able to wait forever behind a lock.
     *
     * It is called only after {@see self::openSource()} has confirmed a handle, so the
     * unreachable case never reaches here — that one is named by the resolver as a
     * ConnectionUnreachable skip. An engine with no known session-bounding statement is
     * left alone by the guard.
     */
    private function boundSourceSession(string $connectionName): Closure
    {
        $connection = $this->database->connection($connectionName);

        $budget = new CaptureConnectionResolver($this->drivers, $this->config)->sessionBudget();
        $guard = new SessionGuard($budget);

        // Snapshot BEFORE applying, or the snapshot records our own bound and "restoring"
        // would cement exactly what it is supposed to undo.
        $snapshot = $guard->snapshot($connection);

        $guard->apply($connection);

        return static fn () => $guard->restore($connection, $snapshot);
    }

    /**
     * The configured `migration_paths`, or null when none are set. Read leniently —
     * the config validator owns malformed values, loudly — so a bad entry never
     * throws mid-run. An empty list means "not set": fall through to the application's
     * registered paths, exactly as a run with no --path does.
     *
     * @return list<string>|null
     */
    private function configuredMigrationPaths(): ?array
    {
        $configured = $this->config->get('sqlens.migration_paths');

        if (! is_array($configured)) {
            return null;
        }

        $paths = array_values(array_filter($configured, is_string(...)));

        return $paths === [] ? null : $paths;
    }

    /** @param  list<string>  $migrationPaths */
    private function resolvePending(string $connectionName, array $migrationPaths, bool $includeVendorMigrations): PendingResolution
    {
        $resolver = new PendingMigrationResolver(
            $this->database,
            $this->migrator,
            $migrationPaths,
            'migrations',
            $this->projectRoot(),
            $includeVendorMigrations,
        );

        return $resolver->resolve($connectionName);
    }

    /**
     * The single `--file` subject, or a named failure. The resolver opens no
     * connection — the fast path stays DB-free.
     *
     * @param  list<string>  $migrationPaths
     */
    private function resolveSingleFile(string $file, array $migrationPaths, string $connectionName): PendingMigration|SingleFileFailure
    {
        return new SingleFileResolver($this->migrator, $migrationPaths, $this->projectRoot())->resolve($file, $connectionName);
    }

    /** The `--file`-could-not-resolve outcome: no findings, the failure carried, misconfiguration exit. */
    private function fileMisconfiguration(SingleFileFailure $failure, RunContext $context, CaptureMode $mode, string $connectionName): LintOutcome
    {
        $result = Result::of([], $this->metadata($mode));

        return new LintOutcome($result, $context, $this->exitCodes->resolve($result, $context, true), $connectionName, fileFailure: $failure);
    }

    /**
     * The rule ids a baseline names that no rule of any driver carries.
     *
     * Reuses the audit half's check rather than repeating it — a second implementation would be a
     * second thing to keep in step, and the two would disagree exactly once, quietly.
     *
     * A baseline that cannot be READ falls through silently: it has its own refusal further along
     * with its own message, and answering here would replace "this file is unparseable" with "its
     * rule ids could not be checked" — the less useful half of the same news, arriving first.
     *
     * @return list<ConfigViolation>
     */
    private function baselineViolations(): array
    {
        try {
            $baseline = new ConfiguredBaseline($this->config)->forRun();
        } catch (UnreadableBaseline) {
            return [];
        }

        return BaselineRuleIds::violations($baseline, $this->drivers->everyRule());
    }

    /**
     * The refusal for a configuration that names rules which do not exist: no findings about
     * migrations, one notice per violation, and the misconfiguration exit.
     *
     * @param  list<ConfigViolation>  $violations
     */
    private function refusedConfig(array $violations, RunContext $context, CaptureMode $mode, string $connectionName, string $configuredDriver, bool $strict, ResolvedServerVersion $resolvedVersion): LintOutcome
    {
        $findings = array_map(
            // UNDETERMINED, not a fail, and that is the same choice the audit half makes. The run
            // did not find a problem in a migration — it could not run at all, which is what the
            // third value is for. It also decides whether a reader ever sees this: a fail is level
            // gated, so a refusal reported as one vanishes from a run at a lower level, and the
            // command would exit non-zero while the report said nothing about why. Measured.
            fn (ConfigViolation $violation): Finding => Finding::undetermined(
                RunnerNotice::InvalidConfigReference->value,
                RunnerNotice::MESSAGE_PREFIX,
                $violation->message().' Nothing was linted: a baseline that names a rule which does not '
                    .'exist suppresses nothing while looking set, and — unlike an ignore list — it cannot be '
                    .'noticed from the output, because an entry that matches nothing produces exactly what a '
                    .'matching entry produces once the code is fixed.',
                UndeterminedReason::NotConfigured,
                Location::inCallsite('baseline', 0, 'connection '.$connectionName, $this->projectRoot()),
                RunnerNotice::InvalidConfigReference->category(),
                RunnerNotice::InvalidConfigReference->level(),
                RunnerNotice::InvalidConfigReference->stability(),
                RunnerNotice::InvalidConfigReference->documentationUrl(),
                // Built from the CONFIGURED driver name rather than from a resolved driver: this
                // refusal happens before the engine is resolved, on purpose, and a finding about
                // the project's own files does not need the engine to be supported to be true. The
                // name is what `database.connections.<name>.driver` says, which is all a reader
                // needs to know which run this was.
                new SubjectContext($configuredDriver, $context->profile->value, $strict, $resolvedVersion, $connectionName),
            ),
            $violations,
        );

        return new LintOutcome(Result::of($findings, $this->metadata($mode)), $context, ExitCode::Misconfiguration, $connectionName);
    }

    /** The unsupported-engine outcome: no findings, the failure carried, misconfiguration exit. */
    private function unsupported(DriverResolutionFailure $failure, RunContext $context, CaptureMode $mode, string $connectionName): LintOutcome
    {
        $result = Result::of([], $this->metadata($mode));

        return new LintOutcome($result, $context, $this->exitCodes->resolve($result, $context, true), $connectionName, $failure);
    }

    /**
     * The unresolvable-pending outcome: one named LINT.SKIPPED undetermined finding,
     * never an empty pass.
     *
     * @param  list<string>  $migrationPaths
     */
    private function skipped(PendingResolution $resolution, string $connectionName, array $migrationPaths, SubjectContext $subjectContext, RunContext $context, CaptureMode $mode): LintOutcome
    {
        // A skipped resolution always carries a reason (the type enforces it); the
        // throw guards that invariant rather than inventing a default.
        $reason = $resolution->skip ?? throw new LogicException('An unresolved pending resolution without a skip reason is unconstructible.');

        $result = Result::of([$this->skipFinding($reason, $connectionName, $migrationPaths, $subjectContext)], $this->metadata($mode));

        return new LintOutcome($result, $context, $this->exitCodes->resolve($result, $context, false), $connectionName);
    }

    /** @param  list<string>  $migrationPaths */
    private function skipFinding(PendingSkipReason $reason, string $connectionName, array $migrationPaths, SubjectContext $subjectContext): Finding
    {
        // The skip is about the migration source for a connection, not a single
        // migration, so it is located at the first configured path as a callsite.
        $path = $migrationPaths[0] ?? 'database/migrations';

        return Finding::undetermined(
            $reason->ruleId(),
            RunnerNotice::MESSAGE_PREFIX,
            $reason->description(),
            $reason->undeterminedReason(),
            Location::inCallsite($path, 0, 'connection '.$connectionName, $this->projectRoot()),
            RunnerNotice::Skipped->category(),
            RunnerNotice::Skipped->level(),
            RunnerNotice::Skipped->stability(),
            // The id here is dynamic (`LINT.SKIPPED.<reason>`), but every skip reason shares one
            // page, so the URL comes from the family rather than from the specific id.
            RunnerNotice::Skipped->documentationUrl(),
            $subjectContext,
        );
    }

    /** The capture-layer producers the run reports through — the shipped set, never a second list. */
    private function collector(): CaptureFindingCollector
    {
        return new CaptureFindingCollector(
            CaptureFindingCatalog::rules(),
            CaptureFindingCatalog::detectors(),
        );
    }

    /**
     * The reproducibility header, populated with this run's parameters: the config
     * collector supplies the severity floor, strict flags, profile and package
     * version; this run overrides the mode (the flag, not config), the addressed
     * server version, the active level (flag over config), the level gate's
     * active/hidden rule counts, the categories the run was scoped to, the discovered
     * tool versions, and the resolved strict-tool flag.
     *
     * @param  list<string>  $activeCategories
     * @param  array<string, string>  $toolVersions
     */
    private function buildContext(string $connectionName, CaptureMode $mode, ResolvedServerVersion $resolvedVersion, int $level, int $activeRules, int $hiddenRules, array $activeCategories, array $toolVersions, bool $strictTools, bool $roundtrip, ?DriverResolutionFailure $floorFailure = null, ?GuardDecision $guard = null): RunContext
    {
        $base = $this->contextCollector->collect();

        return new RunContext(
            // The marker rides IN the version string rather than in a new header key. One
            // change then reaches all three reporters, the header's key set stays closed (a
            // contract test pins it), and the JSON schema version does not move. The field has
            // carried prose since the first build — "unknown (no server version could be
            // determined)" — so nothing can be parsing it as a bare semver.
            //
            // It states a PREMISE of the run, not a finding, which is why suppressing the
            // notice does not remove it: baselining a finding hides the finding, it does not
            // make the server newer.
            serverVersions: [new ReportedServerVersion($connectionName, $this->headerVersion($resolvedVersion, $floorFailure), $resolvedVersion->source)],
            toolVersions: $toolVersions,
            mode: ReportingCaptureMode::from($mode->value),
            profile: $base->profile,
            strictTools: $strictTools,
            strictUndetermined: $base->strictUndetermined,
            roundtrip: $roundtrip,
            sqlensVersion: $base->sqlensVersion,
            level: $level,
            minSeverity: $base->minSeverity,
            activeRuleCount: $activeRules,
            hiddenRuleCount: $hiddenRules,
            activeCategories: $activeCategories,
            admittedStability: $base->admittedStability,
            // Null for every run that asked no guard — a pretend lint creates nothing. Passed
            // through rather than re-derived: the decision the captor obeyed IS the one the header
            // reports, so the two can never describe different runs.
            guard: $guard,
            // From the base rather than read again: the collector owns that read, and this runner
            // already has its answer in hand.
            guardProfile: $base->guardProfile,
        );
    }

    /** The strict-tool flag: the CLI flag when given (it overrides), else the config's. */
    private function resolveStrictTools(?bool $strictTools): bool
    {
        return $strictTools ?? ($this->config->get('sqlens.strict_tools') === true);
    }

    /**
     * The versions of the tools that WERE found — name => version — for the header. A
     * missing tool contributes nothing here (it is reported as a finding instead), so
     * the header lists exactly what actually ran.
     *
     * @param  list<ToolDiagnostic>  $diagnostics
     * @return array<string, string>
     */
    private function toolVersions(array $diagnostics): array
    {
        $versions = [];

        foreach ($diagnostics as $diagnostic) {
            if ($diagnostic->isAvailable() && is_string($diagnostic->version)) {
                $versions[$diagnostic->tool->name()] = $diagnostic->version;
            }
        }

        return $versions;
    }

    /**
     * Whether any tool is a fixable not-found — the only absence a strict run fails on.
     *
     * @param  list<ToolDiagnostic>  $diagnostics
     */
    private function hasStrictFailure(array $diagnostics): bool
    {
        return array_any($diagnostics, fn (ToolDiagnostic $diagnostic): bool => $diagnostic->failsStrict());
    }

    /**
     * The strict-tool stop: no capture, the misconfiguration exit, and one named
     * finding per missing tool so the reason is never anonymous.
     *
     * @param  list<ToolDiagnostic>  $diagnostics
     */
    private function strictToolStop(array $diagnostics, string $connectionName, SubjectContext $subjectContext, RunContext $context, CaptureMode $mode): LintOutcome
    {
        $findings = [];

        foreach ($diagnostics as $diagnostic) {
            if ($diagnostic->isMissing()) {
                $findings[] = $this->missingToolFinding($diagnostic, $connectionName, $subjectContext);
            }
        }

        $result = Result::of($findings, $this->metadata($mode));

        return new LintOutcome($result, $context, $this->exitCodes->resolve($result, $context, true), $connectionName);
    }

    /**
     * A missing tool as an undetermined finding: it names the tool, what it would have
     * added, and — for a platform with no build — that the absence is a platform
     * reality rather than a fixable install.
     *
     * Delegated to {@see MissingToolNotice}, which the audit route needs verbatim.
     *
     * Kept as a method rather than inlined at both call sites: this runner calls it from two
     * places, and threading the project root through each of them would put the same three
     * arguments in two spots that must never disagree.
     */
    private function missingToolFinding(ToolDiagnostic $diagnostic, string $connectionName, SubjectContext $subjectContext): Finding
    {
        return MissingToolNotice::for(RunnerNotice::SkippedMissingTool, $diagnostic, $connectionName, $this->projectRoot(), $subjectContext);
    }

    /**
     * What the committed debt account and this run say about each other, as findings.
     *
     * Returns nothing at all when the caller asked for no debt pass or the project switched the
     * account off — a project that has not adopted it should not be told about a file it never
     * created.
     *
     * @param  list<Finding>  $findings  the run's findings so far; debts are derived FROM them
     * @param  list<Rule>  $rules  the rules that ran, so a finding can be traced to the one claiming it
     * @return list<Finding>
     */
    private function debtFindings(?DebtMode $debt, array $findings, array $rules, string $driverKey, SubjectContext $subjectContext, bool $singleFile): array
    {
        if (! $debt instanceof DebtMode || $this->config->get('sqlens.deploy.debt.enabled') !== true) {
            return [];
        }

        // A recording run asked for from the single-file view. Named and undetermined rather than
        // refused: `--file` is the pre-commit path, and failing the hook over a flag combination
        // would block a commit instead of doing the lint the hook exists for. The mode falls back
        // to reading, and the fall-back is the finding rather than a silence.
        $notRecordable = $debt === DebtMode::Record && $singleFile;

        if ($notRecordable) {
            $debt = DebtMode::Check;
        }

        // Passed on WITHOUT narrowing, deliberately. The registry answers `DriverCanonicalization`
        // or a named failure, and a guard here would be an unreachable branch in the middle of the
        // run: the same registry decides whether the driver is known at all, so a driver with no
        // canonicalization is refused at RESOLUTION — exit 2, with a message about the engine —
        // and never reaches a line of this method. Measured, not assumed. The registrar takes the
        // union and answers nothing for a failure, which is the one place that decision belongs.
        $canonicalization = $this->extensions->forDriver($driverKey);

        $configured = $this->config->get('sqlens.deploy.debt.path');
        $path = is_string($configured) && $configured !== '' ? $configured : DebtLedger::DEFAULT_PATH;
        $absolute = $this->projectRoot().'/'.$path;

        $ledger = DebtLedger::load(new Filesystem, $absolute);

        // A ledger this build cannot act on is the one place "no debts" would be a lie in the most
        // comfortable direction: a clean report at exactly the moment nobody can say whether the
        // project is clean.
        if (! $ledger->isUsable()) {
            return [$this->debtNotice(
                RunnerNotice::DebtLedgerUnreadable,
                $ledger->refusal instanceof DebtLedgerRefusal ? $ledger->refusal->detail : 'the debt ledger could not be read',
                $ledger->refusal instanceof DebtLedgerRefusal ? $ledger->refusal->reason : UndeterminedReason::DebtLedgerUnreadable,
                $path,
                $subjectContext,
            )];
        }

        $reconciliation = DebtReconciliation::of(
            $ledger,
            DebtRegistrar::candidates($findings, $rules, $canonicalization, gmdate('Y-m-d')),
            // This run reads MIGRATIONS. A debt the catalog knows about and no migration explains
            // is invisible here — not absent, invisible — so it is outside what this run may judge.
            // Before the scope existed, recording from lint would have deleted every such entry on
            // its next pass, for the honest reason that it could not see them.
            DebtRegistrar::scopeOf($rules, DebtOrigin::Migration),
        );

        $notices = [];

        if ($notRecordable) {
            $notices[] = $this->debtNotice(
                RunnerNotice::DebtNotRecordable,
                'a recording run was asked for with --file, and one migration cannot tell an open debt '
                .'from a settled one — the migration that settles it is a different file. Recording from '
                .'this view would remove entries for the honest reason that this run could not see them, '
                .'so nothing was written. Run it over the full pending set to record.',
                UndeterminedReason::StructurallyNotApplicable,
                'fast-path',
                $subjectContext,
            );
        }

        foreach ($reconciliation->unrecorded as $entry) {
            $notices[] = $this->debtNotice(
                RunnerNotice::DebtUnrecorded,
                sprintf(
                    '%s on `%s` is an open end this run owes, and the debt ledger has no entry for it. '
                    .'Finish it, or run `sqlens:lint --debt=record` to start counting how long it has '
                    .'been outstanding.',
                    $entry->kind,
                    $entry->object,
                ),
                null,
                $entry->object,
                $subjectContext,
                $entry,
            );
        }

        foreach ($reconciliation->stale as $entry) {
            $notices[] = $this->debtNotice(
                RunnerNotice::DebtStaleEntry,
                sprintf(
                    'The ledger records %s on `%s` and this run does not owe it — most likely somebody '
                    .'finished it. `sqlens:lint --debt=record` removes the entry. If this run could not '
                    .'have seen it (a narrowed level or category), leave it.',
                    $entry->kind,
                    $entry->object,
                ),
                null,
                $entry->object,
                $subjectContext,
                $entry,
            );
        }

        foreach ($reconciliation->acknowledgedGone as $entry) {
            $notices[] = $this->debtNotice(
                RunnerNotice::DebtAcknowledgedGone,
                sprintf(
                    '%s on `%s` is recorded as knowingly carried ("%s") and this run did not detect it. '
                    .'It is KEPT rather than removed: the written reason is what would be lost, and a '
                    .'debt that reappears later would come back with its age restarted. Remove the entry '
                    .'by hand once you are sure it is settled.',
                    $entry->kind,
                    $entry->object,
                    $entry->reason === '' ? 'no reason recorded' : $entry->reason,
                ),
                null,
                $entry->object,
                $subjectContext,
                $entry,
            );
        }

        // An acknowledgment whose review date has passed. Read over the RECORDED set rather than
        // over any one list above, because it applies to an entry whether or not this run still
        // detects the debt — the decision expires on its own schedule.
        $today = gmdate('Y-m-d');

        foreach ($reconciliation->recorded as $entry) {
            if ($entry->state !== DebtState::Acknowledged) {
                continue;
            }
            if ($entry->reviewAt === null) {
                continue;
            }
            if ($entry->reviewAt >= $today) {
                continue;
            }
            $notices[] = $this->debtNotice(
                RunnerNotice::DebtAcknowledgmentExpired,
                sprintf(
                    'The decision to carry %s on `%s` ("%s") was due for review on %s. The debt is '
                    .'not worse than it was — the DECISION has expired. Renew it with a new '
                    .'`review_at`, or settle the debt and let the entry go.',
                    $entry->kind,
                    $entry->object,
                    $entry->reason,
                    $entry->reviewAt,
                ),
                null,
                $entry->object,
                $subjectContext,
                $entry,
            );
        }

        // The write, and the only one this package makes outside a report. It happens after the
        // findings are built, so a recording run reports exactly what it wrote.
        if ($debt === DebtMode::Record && ! $reconciliation->isSettled()) {
            DebtLedger::of($reconciliation->recorded)->write(new Filesystem, $absolute);
        }

        return $notices;
    }

    /**
     * One debt notice, located on the object it is about rather than on a file nobody can open.
     *
     * One repository-side debt notice.
     *
     * The ENTRY is what makes the finding machine-readable, and it arrives here rather than at each
     * call site for the reason {@see Finding::withStatistics()} exists: one attachment point cannot
     * be forgotten, six can. It is nullable because two of these notices are statements about the
     * ACCOUNT — an unreadable ledger, a fast-path run that must not record — and there is no debt
     * for them to describe. Giving those a `debt_kind` would invent one out of the fact that none
     * could be read.
     *
     * The age is deliberately NOT computed here. This side reconciles what a run owes against the
     * file and holds no reference date; {@see DebtContext::unaged()} says so by name rather than by
     * passing a zero that would read as "recorded today".
     */
    private function debtNotice(RunnerNotice $notice, string $message, ?UndeterminedReason $reason, string $object, SubjectContext $subjectContext, ?DebtEntry $entry = null): Finding
    {
        $location = Location::inCallsite('debt:'.$object, 0, $notice->value, $this->projectRoot());

        $finding = $reason instanceof UndeterminedReason
            ? Finding::undetermined($notice->value, RunnerNotice::MESSAGE_PREFIX, $message, $reason, $location, $notice->category(), $notice->level(), $notice->stability(), $notice->documentationUrl(), $subjectContext)
            : Finding::fail($notice->value, RunnerNotice::MESSAGE_PREFIX, $message, $location, $notice->category(), $notice->level(), $notice->stability(), $notice->documentationUrl(), $subjectContext);

        return $entry instanceof DebtEntry ? $finding->withDebt(DebtContext::unaged($entry)) : $finding;
    }

    /**
     * A baseline entry whose source did not answer this run.
     *
     * Undetermined, never a failure and never silence. The entry describes a finding somebody
     * accepted from a tool that was not asked — so it is neither fixed nor broken, and the only
     * honest thing to say is that nobody looked.
     */
    private function unverifiableBaselineFinding(BaselineEntry $entry, string $connectionName, SubjectContext $subjectContext): Finding
    {
        return Finding::undetermined(
            RunnerNotice::SkippedMissingTool->value,
            RunnerNotice::MESSAGE_PREFIX,
            sprintf(
                'The baseline accepts %s, and the tool that reports it did not run — so this entry was not checked rather than fixed. It stays in the file.',
                $entry->ruleId,
            ),
            UndeterminedReason::MissingExternalTool,
            Location::inCallsite('baseline:'.$entry->ruleId, 0, 'connection '.$connectionName, $this->projectRoot()),
            RunnerNotice::SkippedMissingTool->category(),
            RunnerNotice::SkippedMissingTool->level(),
            RunnerNotice::SkippedMissingTool->stability(),
            RunnerNotice::SkippedMissingTool->documentationUrl(),
            $subjectContext,
        );
    }

    /** The active strictness level: the flag when given (the command validated it), else the config's. */
    private function resolveLevel(?int $level): int
    {
        if ($level !== null) {
            return $level;
        }

        $configured = $this->config->get('sqlens.level');

        return is_int($configured) ? max(0, min(9, $configured)) : 0;
    }

    /**
     * The categories a run is scoped to: the flag values when given (the command validated them),
     * else the config's `sqlens.categories`. An empty result means no filter — every category —
     * exactly as an empty config list does.
     *
     * Resolved by {@see CategorySelection::forRun()} rather than here, because the audit suite has
     * to answer this identically and a second reading of one key is how the two suites started
     * disagreeing about what `--category` defaults to.
     *
     * @param  list<string>|null  $categories
     * @return list<Category>
     */
    private function resolveCategories(?array $categories): array
    {
        return CategorySelection::forRun($categories, $this->config->get('sqlens.categories'))->categories;
    }

    /**
     * The suppression chain for this run, built from the lint context: the resolved
     * baseline file, the `ignore` config block, the reasons a project has explicitly
     * accepted living without, and whether it has opted in project-wide to destructive
     * operations. The order (baseline · config · annotation · destructive opt-in) and
     * the mechanism are owned by the suppression layer; this only wires them.
     */
    private function suppressionResolver(bool $applyBaseline): SuppressionResolver
    {
        return SuppressionResolver::for(
            $applyBaseline ? $this->baselineFile() : BaselineFile::of([]),
            $this->config->get('sqlens.ignore'),
            $this->allowedUndetermined(),
            $this->allowsDestructiveProjectWide(),
        );
    }

    /**
     * Whether the project has opted in project-wide to destructive operations, from
     * `sqlens.allow_destructive`. Read leniently — the config validator owns a malformed
     * value, loudly — so a non-boolean never throws mid-run; only a literal `true`
     * grants it. It never HIDES a destructive finding: the reporting layer turns it into
     * a named, visible suppression.
     */
    private function allowsDestructiveProjectWide(): bool
    {
        return $this->config->get('sqlens.allow_destructive') === true;
    }

    /**
     * One suppression candidate per finding: its fingerprint (rule id + location; the
     * excerpt is empty because a run produces only findings with no canonical
     * statement today), its ordinal among identical fingerprints, and the migration
     * it came from as the annotation carrier — so a class-level `#[SqlensIgnore]` can
     * reach it even when the migration produced no statements.
     *
     * @param  list<Finding>  $findings
     * @return list<SuppressionCandidate>
     */
    private function candidates(array $findings, CaptureRun $run, SubjectContext $context): array
    {
        $carriers = [];
        foreach ($run->results as $result) {
            $carriers[$result->migrationClass] = $result->annotationCarrier($context);
        }

        $ordinals = [];
        $candidates = [];

        foreach ($findings as $finding) {
            $fingerprint = FindingFingerprint::of($finding->ruleId, $finding->location, Fingerprint::fromValue(''));
            $ordinal = $ordinals[$fingerprint->value] ?? 0;
            $ordinals[$fingerprint->value] = $ordinal + 1;

            $migrationClass = $finding->location->migrationClass;
            $subject = is_string($migrationClass) ? ($carriers[$migrationClass] ?? null) : null;

            $candidates[] = new SuppressionCandidate($finding, $fingerprint, $ordinal, $subject);
        }

        return $candidates;
    }

    /**
     * The baseline the run suppresses against: the file at `sqlens.baseline.path`, or
     * an empty baseline when none is configured or present. A broken baseline is NOT
     * applied — the findings it would have accepted stay visible (the safe direction),
     * never silently hidden.
     */
    private function baselineFile(): BaselineFile
    {
        return new ConfiguredBaseline($this->config)->forRun();
    }

    /**
     * The undetermined reasons a project has explicitly accepted living without, from
     * `sqlens.suppression.allow_undetermined`. Read leniently — the config validator
     * owns malformed values, loudly — so an unknown reason never throws mid-run.
     *
     * @return list<UndeterminedReason>
     */
    private function allowedUndetermined(): array
    {
        $configured = $this->config->get('sqlens.suppression.allow_undetermined');

        if (! is_array($configured)) {
            return [];
        }

        return array_values(array_filter(
            array_map(static fn (mixed $value): ?UndeterminedReason => is_string($value) ? UndeterminedReason::tryFrom($value) : null, $configured),
        ));
    }

    /**
     * The undetermined finding for a category filter that admitted no rules: it names
     * the scope so the emptiness is a visible, actionable result rather than a pass.
     *
     * @param  list<string>  $activeCategories
     */
    private function noActiveRulesFinding(array $activeCategories, string $connectionName, SubjectContext $subjectContext): Finding
    {
        return Finding::undetermined(
            RunnerNotice::NoActiveRules->value,
            RunnerNotice::MESSAGE_PREFIX,
            sprintf('No rules are active for the requested categories (%s); the run checked nothing. Widen the --category scope or the level.', implode(', ', $activeCategories)),
            UndeterminedReason::NoActiveRules,
            Location::inCallsite('--category', 0, 'connection '.$connectionName, $this->projectRoot()),
            RunnerNotice::NoActiveRules->category(),
            RunnerNotice::NoActiveRules->level(),
            RunnerNotice::NoActiveRules->stability(),
            RunnerNotice::NoActiveRules->documentationUrl(),
            $subjectContext,
        );
    }

    /**
     * Resolve the server version this run reasons about — the flag, the config pin,
     * the real detected version, or a named undetermined — in that precedence. The
     * raw banner is read from the already-open handle without connecting; parsing and
     * precedence live in the driver-neutral resolver.
     */
    private function resolveVersion(string $connectionName, ?string $assumeServerVersion, ?string $banner): ResolvedServerVersion
    {
        return $this->versionResolver->resolve($this->driverKey($connectionName), $assumeServerVersion, $banner);
    }

    /**
     * The server's RAW version banner, through the one acquisition unit, or null.
     *
     * It opens nothing — the unit reads the PDO the connection is already holding — so on a
     * cold CLI process this is null, and that is the ordinary correct answer rather than a
     * fault: a `--file` run has no database at all, and a fresh `artisan` process has not
     * touched one yet. A throwing connection collapses to null for the same reason the inline
     * try/catch did: an unreachable connection is named by the pending resolver, not here.
     *
     * Separated from {@see self::resolveVersion()} because the raw banner is needed a second
     * time, for a different question: the floor is judged on the string the SERVER sent, never
     * on the normalized form, and the two answers must come from one acquisition.
     */
    private function detectedBanner(string $connectionName): ?string
    {
        try {
            return $this->versions->resolve($connectionName);
        } catch (Throwable) {
            return null;
        }
    }

    /**
     * The header's version string, marked when the run reasons from an unsupported version.
     *
     * Loud on purpose. The owner's instruction was Option B "mit deutlichen hinweisen" — a
     * notice a reader scrolls past defeats the whole point, because acting on the report is
     * exactly what this warns against.
     */
    private function headerVersion(ResolvedServerVersion $resolvedVersion, ?DriverResolutionFailure $floorFailure): string
    {
        $version = $resolvedVersion->headerVersion();

        if ($floorFailure?->reason !== DriverResolutionReason::VersionBelowFloor) {
            return $version;
        }

        return sprintf(
            '%s — BELOW THE SUPPORTED FLOOR of %s: every finding in this report may be wrong in both directions',
            $version,
            $floorFailure->placeholders['required'] ?? 'a supported version',
        );
    }

    /**
     * Whether the version this run REASONS FROM clears the driver's floor.
     *
     * A pin is what every finding in a lint report describes, so the pin is what gets judged
     * when one is set. The other direction — a pin ABOVE a below-floor live server — is not
     * judged here, and that is not silence either: `LINT.VERSION_SKEW` already names both.
     *
     * Only asked when a version actually resolved. "No version at all" and "an unreadable pin"
     * are different cases, and both already carry notices of their own; a floor verdict on top
     * would be the same gap reported twice under a second name.
     *
     * The RAW string goes in on BOTH paths, never the normalized form — and the pin path is not
     * the obvious half. A MariaDB banner normalizes to a plain number below every floor SQLens
     * has, so a normalized input makes the floor unit's attribution guard blind and it reports
     * "upgrade your MySQL" about a product the operator does not run.
     *
     * Found by the wiring proof rather than by reading: six of its seven arms passed on a first
     * version that handed the PARSED pin over here, and the seventh — a project pinning
     * `5.5.68-MariaDB` — produced exactly that wrong advice. Normalizing costs nothing here
     * either, because the floor unit parses whatever it is given.
     */
    private function floorFailure(Driver $driver, ResolvedServerVersion $resolvedVersion, ?string $banner, ?string $pin): ?DriverResolutionFailure
    {
        if (! $resolvedVersion->isResolved()) {
            return null;
        }

        // Both sides are non-empty whenever the version RESOLVED — an assumed source means a pin
        // was read and parsed, a detected one means a banner was. The emptiness check is therefore
        // a type narrowing rather than a behavior, and it lives inside the expression instead of
        // as its own branch: as a statement it was a line no test could ever reach, and an
        // unreachable line in a 100%-coverage repo is a claim nobody can honor.
        $judged = $resolvedVersion->source === VersionSource::Assumed ? $pin : $banner;

        $failure = is_string($judged) && $judged !== '' ? new ServerVersionFloor()->check($driver, $judged) : null;

        // ONLY a genuine below-floor verdict is reported from here. The floor unit also refuses to
        // judge a banner it cannot attribute — but on THIS path that refusal cannot arrive:
        //
        //   · a pin cannot carry a vendor suffix at all (`parsePin` rejects every suffixed string,
        //     measured, so an unattributable pin never resolves and the floor is never asked), and
        //   · a detected banner naming another engine is the ENGINE check's business, and that
        //     check runs first — it refuses the run before this notice could be built.
        //
        // Reporting it anyway would mean carrying a message for a state this path cannot reach,
        // and the coverage gate is right to call that out rather than let it sit. The AUDIT path
        // keeps the case, because there it is genuinely reachable and genuinely proven.
        return $failure?->reason === DriverResolutionReason::VersionBelowFloor ? $failure : null;
    }

    /**
     * The pin string as the project WROTE it — flag first, then config, exactly the precedence
     * the resolver applies.
     *
     * Raw on purpose: this is the value the floor unit has to see in order to recognize that it
     * describes another engine. Re-derived here rather than threaded because the resolver keeps
     * only the parsed form, and parsing is the very thing that loses the evidence.
     */
    private function configuredPin(?string $assumeServerVersion): ?string
    {
        if (is_string($assumeServerVersion) && $assumeServerVersion !== '') {
            return $assumeServerVersion;
        }

        $configured = $this->config->get('sqlens.assume_server_version');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }

    /** The connection's configured driver key, for driver-aware version parsing. */
    private function driverKey(string $connectionName): string
    {
        $driver = $this->config->get("database.connections.{$connectionName}.driver");

        return is_string($driver) ? $driver : 'unknown';
    }

    /**
     * A version-dependent rule the run could not judge, because no server version could
     * be determined (a fast-path run without a pin, an unreachable server). It carries
     * the rule's OWN id and metadata — a reader sees which rule was left unchecked and
     * why, and the level and severity axes stay separate — with a named reason that
     * points at the pin, never a silent skip and never a guessed default.
     *
     * The advice follows the cause. Telling someone to pin `assume_server_version` when
     * they already did, and it is the pin that is broken, sends them round in a circle
     * looking for a setting they are staring at.
     */
    private function versionUndeterminedFinding(Rule $rule, ResolvedServerVersion $resolvedVersion, string $connectionName, SubjectContext $subjectContext): Finding
    {
        $advice = $resolvedVersion->unreadablePin === null
            ? 'Pin assume_server_version to check it deterministically.'
            : sprintf('The assume_server_version pin "%s" could not be read as a version; correct it to check this deterministically.', $resolvedVersion->unreadablePin);

        return Finding::undetermined(
            $rule->id(),
            $rule->messagePrefix(),
            sprintf('%s is version-dependent, but no server version could be determined, so it was not evaluated. %s', $rule->id(), $advice),
            UndeterminedReason::UnknownServerVersion,
            Location::inCallsite($rule->id(), 0, 'connection '.$connectionName, $this->projectRoot()),
            $rule->category(),
            $rule->level(),
            $rule->stability(),
            $rule->documentationUrl(),
            $subjectContext,
            $rule->severity(),
        );
    }

    /**
     * A statistics-dependent rule the run could not judge, because statistics are on
     * but no reader is available in this build. It carries the rule's OWN id and
     * metadata — a reader sees which rule was left unchecked and why — with the named
     * `StatisticsUnavailable` reason, never a silent skip and never a guessed pass.
     */
    private function statisticsUnavailableFinding(Rule $rule, string $connectionName, SubjectContext $subjectContext): Finding
    {
        return Finding::undetermined(
            $rule->id(),
            $rule->messagePrefix(),
            sprintf('%s reasons about the server statistics, but no statistics reader is available in this build, so it was not evaluated. It will run once the audit suite lands.', $rule->id()),
            UndeterminedReason::StatisticsUnavailable,
            Location::inCallsite($rule->id(), 0, 'connection '.$connectionName, $this->projectRoot()),
            $rule->category(),
            $rule->level(),
            $rule->stability(),
            $rule->documentationUrl(),
            $subjectContext,
            $rule->severity(),
        );
    }

    /** The version-skew finding: the pin disagreed with the connected server. */
    private function skewFinding(ResolvedServerVersion $resolvedVersion, string $connectionName, SubjectContext $subjectContext): Finding
    {
        // Both are non-null whenever hasSkew() holds; the throws guard that invariant.
        $pin = $resolvedVersion->version ?? throw new LogicException('A skew without an assumed version is unconstructible.');
        $detected = $resolvedVersion->skewDetected ?? throw new LogicException('A skew without a detected version is unconstructible.');

        return Finding::undetermined(
            RunnerNotice::VersionSkew->value,
            RunnerNotice::MESSAGE_PREFIX,
            sprintf('The assumed server version %s disagrees with the version the connected server reported (%s); the result reflects the pin, not the live instance.', $pin->toString(), $detected->toString()),
            UndeterminedReason::AssumedVersionSkew,
            Location::inCallsite('assume_server_version', 0, 'connection '.$connectionName, $this->projectRoot()),
            RunnerNotice::VersionSkew->category(),
            RunnerNotice::VersionSkew->level(),
            RunnerNotice::VersionSkew->stability(),
            RunnerNotice::VersionSkew->documentationUrl(),
            $subjectContext,
        );
    }

    /**
     * The `assume_server_version` pin could not be read as a version.
     *
     * Reported under its own id rather than folded into the per-rule undetermined
     * findings, because it is true of the RUN and not of any one rule: it is worth
     * saying even when nothing version-dependent was active, and it is the one line
     * that names the actual fix. Nothing is assumed in its place — falling back to the
     * detected version or to the supported baseline would let a project keep believing
     * it audits against a fixed version while every run reasons about something else.
     */
    private function unreadablePinFinding(string $pin, string $connectionName, SubjectContext $subjectContext): Finding
    {
        return Finding::undetermined(
            RunnerNotice::VersionPinUnreadable->value,
            RunnerNotice::MESSAGE_PREFIX,
            sprintf('The assume_server_version pin "%s" could not be read as a version, and nothing was assumed in its place; version-dependent rules could not be evaluated.', $pin),
            UndeterminedReason::UnreadableServerVersionPin,
            Location::inCallsite('assume_server_version', 0, 'connection '.$connectionName, $this->projectRoot()),
            RunnerNotice::VersionPinUnreadable->category(),
            RunnerNotice::VersionPinUnreadable->level(),
            RunnerNotice::VersionPinUnreadable->stability(),
            RunnerNotice::VersionPinUnreadable->documentationUrl(),
            $subjectContext,
        );
    }

    /**
     * The below-floor notice — an `undetermined`, never a `fail`.
     *
     * A fail would say the schema is wrong. Nothing about the schema is wrong: what is
     * uncertain is whether THIS package's verdicts apply to THIS server, and the third value
     * exists for exactly that distinction. Under `strict_undetermined` it lifts the run to
     * exit 3, which is the pipeline's way of asking a human — never exit 1, which would tell
     * a pipeline the migrations breached a gate.
     */
    private function belowFloorFinding(DriverResolutionFailure $failure, VersionSource $source, string $connectionName, SubjectContext $subjectContext): Finding
    {
        return Finding::undetermined(
            RunnerNotice::ServerBelowFloor->value,
            RunnerNotice::MESSAGE_PREFIX,
            $this->belowFloorMessage($failure, $source),
            $failure->undeterminedReason(),
            Location::inCallsite('server_version', 0, 'connection '.$connectionName, $this->projectRoot()),
            RunnerNotice::ServerBelowFloor->category(),
            RunnerNotice::ServerBelowFloor->level(),
            RunnerNotice::ServerBelowFloor->stability(),
            RunnerNotice::ServerBelowFloor->documentationUrl(),
            $subjectContext,
        );
    }

    /**
     * What the reader is told, and it has to be enough to act on.
     *
     * Both directions are named on purpose. "Your server is old" invites the reader to
     * discount the report as over-cautious, when the real exposure is symmetric: a rule may
     * flag behavior this server does not have, AND may stay silent about behavior it does.
     * Which of the two happened cannot be known from here, so both are stated.
     *
     * There is only ONE arm, and that is the caller's doing rather than a simplification: it
     * hands over a below-floor verdict and nothing else, because the other outcomes of the floor
     * unit cannot arrive on this path. See {@see self::floorFailure()} for why.
     */
    private function belowFloorMessage(DriverResolutionFailure $failure, VersionSource $source): string
    {
        $reasoned = $source === VersionSource::Assumed
            ? 'the version this run was pinned to'
            : 'the server this run reached';

        // The two versions come from the failure's own placeholder map rather than from a
        // second parse: it is the one place that already holds both, and re-deriving them
        // here is how the message and the header start to disagree.
        $required = $failure->placeholders['required'] ?? 'a supported version';
        $detected = $failure->placeholders['detected'] ?? 'an older version';

        return sprintf(
            'SQLens supports %s and above; %s reports %s. The findings below were still produced, and they '
            .'may be wrong in BOTH directions — a rule may flag behavior this server does not have, and may '
            .'stay silent about behavior it does. Upgrade the server, or raise the assume_server_version pin '
            .'to a supported version, before treating this report as authoritative.',
            $required,
            $reasoned,
            $detected,
        );
    }

    private function metadata(CaptureMode $mode): RunMetadata
    {
        $profile = $this->config->get('sqlens.profile');

        return new RunMetadata(
            serverVersions: [],
            toolVersions: [],
            mode: $mode,
            profile: is_string($profile) ? $profile : 'local',
            strictTools: $this->config->get('sqlens.strict_tools') === true,
        );
    }

    private function projectRoot(): string
    {
        return $this->app->basePath();
    }
}
