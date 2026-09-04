<?php

declare(strict_types=1);

namespace Pushery\SQLens;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Http\Client\Factory;
use Illuminate\Support\ServiceProvider;
use Laravel\Mcp\Server\McpServiceProvider;
use Override;
use Pushery\SQLens\Agent\Mcp\ServesMcp;
use Pushery\SQLens\Agent\Mcp\StdioServerLoop;
use Pushery\SQLens\Agent\Mcp\StdoutShield;
use Pushery\SQLens\Agent\Mcp\ToolRegistry;
use Pushery\SQLens\Audit\AuditRunner;
use Pushery\SQLens\Audit\AuditRuns;
use Pushery\SQLens\Audit\ProjectManifest;
use Pushery\SQLens\Canonical\Extensions\CanonicalExtensionRegistry;
use Pushery\SQLens\Capture\MigrationPaths;
use Pushery\SQLens\Capture\PendingMigrationResolver;
use Pushery\SQLens\Capture\Shadow\ApplicationShadowClearance;
use Pushery\SQLens\Capture\Shadow\ProductionConnectionDetector;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\CatalogReaders;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SessionBudget;
use Pushery\SQLens\Console\AgentRulesCommand;
use Pushery\SQLens\Console\AuditCommand;
use Pushery\SQLens\Console\BaselineCommand;
use Pushery\SQLens\Console\DoctorCommand;
use Pushery\SQLens\Console\DriftCommand;
use Pushery\SQLens\Console\FormatCommand;
use Pushery\SQLens\Console\LintCommand;
use Pushery\SQLens\Console\McpCommand;
use Pushery\SQLens\Console\PostdeployCommand;
use Pushery\SQLens\Console\PredeployCommand;
use Pushery\SQLens\Console\SecurityCommand;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\PendingResolver;
use Pushery\SQLens\Contracts\ReadsSessionBounds;
use Pushery\SQLens\Contracts\SessionDefenses;
use Pushery\SQLens\Deploy\Checks\DiskHeadroomCheck;
use Pushery\SQLens\Deploy\Checks\ReadOnlyTargetCheck;
use Pushery\SQLens\Deploy\Checks\ReplicationLagCheck;
use Pushery\SQLens\Deploy\Checks\ServerVersionSkewCheck;
use Pushery\SQLens\Deploy\Checks\SessionDefenseAppliedCheck;
use Pushery\SQLens\Deploy\EscalationThresholds;
use Pushery\SQLens\Deploy\PostdeployVerifier;
use Pushery\SQLens\Deploy\PreflightRunner;
use Pushery\SQLens\Deploy\PreflightRuns;
use Pushery\SQLens\Deploy\PreflightService;
use Pushery\SQLens\Deploy\SeverityEscalator;
use Pushery\SQLens\Deploy\TransitionObjectPatterns;
use Pushery\SQLens\Drivers\DriverManager;
use Pushery\SQLens\Drivers\DriverRegistry;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlActivityReader;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlCatalogReader;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlInstanceIdentityReader;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlPoolerReader;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlSecurityReader;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlServerSettingsReader;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlSessionDefense;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlSettingCrossFactCollector;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlStatisticsReader;
use Pushery\SQLens\Drivers\Mysql\Deploy\GrantCheck as MysqlGrantCheck;
use Pushery\SQLens\Drivers\Mysql\Deploy\InvalidIndexCheck as MysqlInvalidIndexCheck;
use Pushery\SQLens\Drivers\Mysql\Deploy\MetadataLockCheck;
use Pushery\SQLens\Drivers\Mysql\Deploy\MysqlSessionDefenseState;
use Pushery\SQLens\Drivers\Mysql\Deploy\MysqlWriteAcceptance;
use Pushery\SQLens\Drivers\Mysql\Deploy\OrphanTransitionObjectCheck as MysqlOrphanTransitionObjectCheck;
use Pushery\SQLens\Drivers\Mysql\Deploy\ServerSettingsCheck as MysqlServerSettingsCheck;
use Pushery\SQLens\Drivers\Mysql\Deploy\UnenforcedConstraintCheck;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlActivityReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlCatalogReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlInstanceIdentityReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlPoolerReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlSecurityReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlServerSettingsReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlSessionDefense;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlSettingCrossFactCollector;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlStatisticsReader;
use Pushery\SQLens\Drivers\Pgsql\Deploy\GrantCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\InvalidIndexCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\LockBlockerCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\NotValidConstraintCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\OrphanTransitionObjectCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\PgsqlSessionDefenseState;
use Pushery\SQLens\Drivers\Pgsql\Deploy\PgsqlWriteAcceptance;
use Pushery\SQLens\Drivers\Pgsql\Deploy\PostdeployInvalidIndexCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\PostdeployNotValidConstraintCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\ReplicationSlotCheck;
use Pushery\SQLens\Drivers\Pgsql\Deploy\ServerSettingsCheck;
use Pushery\SQLens\Format\DialectResolver;
use Pushery\SQLens\Format\FormatConfig;
use Pushery\SQLens\Format\FormatterRegistry;
use Pushery\SQLens\Format\PgFormatterBackend;
use Pushery\SQLens\Format\PhpSqlFormatter;
use Pushery\SQLens\Format\SqlFluffBackend;
use Pushery\SQLens\Guard\GuardManager;
use Pushery\SQLens\Guard\GuardProfile;
use Pushery\SQLens\Guard\Guards\RuntimeDdlGuard;
use Pushery\SQLens\Guard\Guards\SlowQueryGuard;
use Pushery\SQLens\Guard\Guards\StrictModeGuard;
use Pushery\SQLens\Guard\Guards\UnboundRawSqlGuard;
use Pushery\SQLens\Guard\QueryWatcher;
use Pushery\SQLens\Guard\ViolationLogger;
use Pushery\SQLens\Lint\LintRunner;
use Pushery\SQLens\Lint\LintRuns;
use Pushery\SQLens\Lint\ShadowClearance;
use Pushery\SQLens\Reporting\Agent\Redactor;
use Pushery\SQLens\Reporting\CredentialRedaction;
use Pushery\SQLens\Security\Advisory\AdvisoryRefresher;
use Pushery\SQLens\Security\Advisory\EolRepository;
use Pushery\SQLens\Security\Analyse\AnalyseBridge;
use Pushery\SQLens\Security\Analyse\AnalyseMode;
use Pushery\SQLens\Security\Privacy\ModelCastReader;
use Pushery\SQLens\Security\Privacy\ModelDiscovery;
use Pushery\SQLens\Security\Privacy\PrivacyDictionary;
use Pushery\SQLens\Security\Privacy\PrivacyPack;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Security\Privacy\UnencryptedColumnEvaluator;
use Pushery\SQLens\Subjects\SubjectContext;
use Pushery\SQLens\Tools\KnownTools;
use Pushery\SQLens\Tools\MemoizingProcessRunner;
use Pushery\SQLens\Tools\Pgls\PglsContribution;
use Pushery\SQLens\Tools\Pgls\PglsFindingMapper;
use Pushery\SQLens\Tools\Pgls\PglsRuleMap;
use Pushery\SQLens\Tools\Pgls\PglsRunner;
use Pushery\SQLens\Tools\ProcessRunner;
use Pushery\SQLens\Tools\Squawk\SquawkContribution;
use Pushery\SQLens\Tools\Squawk\SquawkDeduplicator;
use Pushery\SQLens\Tools\Squawk\SquawkFindingMapper;
use Pushery\SQLens\Tools\Squawk\SquawkRuleMap;
use Pushery\SQLens\Tools\Squawk\SquawkRunner;
use Pushery\SQLens\Tools\SystemProcessRunner;
use Pushery\SQLens\Tools\ToolContributions;
use Pushery\SQLens\Tools\ToolPositionMapper;

final class SQLensServiceProvider extends ServiceProvider
{
    #[Override]
    public function register(): void
    {
        // The agent redactor, bound once so every surface that writes for an agent — the reporter's
        // render seam and the exporter's artifact seam — masks against the SAME configuration. Two
        // constructions would be two places a connection's values are read.
        $this->app->bind(Redactor::class, fn (Application $app): Redactor => new Redactor(new CredentialRedaction($app->make('config'))));

        $this->mergeConfigFrom(__DIR__.'/../config/sqlens.php', 'sqlens');

        // The registry is bound in its OWN right, and that is the whole point of
        // the extension seam: a consuming application registers a third-party driver
        // by resolving DriverRegistry from the container and calling extend() on it.
        // Built inline inside the manager closure instead, the seam would exist in
        // the class and be unreachable from an app — a public API nobody can use.
        // It is handed the base path so a driver's rules render repo-relative finding
        // locations — the container is where that path is known, so the registry
        // receives it rather than reaching for it.
        $this->app->singleton(
            DriverRegistry::class,
            static fn (Application $app): DriverRegistry => new DriverRegistry(
                $app->basePath(),
                // The raw pgsql lint config, narrowed to its value objects inside the
                // registry — the one place allowed to name a driver. The provider only
                // forwards the values, so it names no engine concept and stays neutral.
                $app->make(Repository::class)->get('sqlens.pgsql.expected_timeouts'),
                $app->make(Repository::class)->get('sqlens.pgsql.max_locks_per_transaction'),
                // What the project states it wants for the settings SQLens declines to have an
                // opinion about. Forwarded raw for the same reason as the two above: the provider
                // names no engine concept, and the registry is the one place allowed to.
                $app->make(Repository::class)->get('sqlens.audit.expect'),
                // Forwarded raw for the same reason as the values above: the provider names no
                // engine concept, and the registry is the one place allowed to.
                $app->make(Repository::class)->get('sqlens.audit.uuid_generated_by'),
                $app->make(Repository::class)->get('sqlens.audit.money_columns'),
                $app->make(Repository::class)->get('sqlens.audit.unused_index'),
                // Forwarded raw like every value above: the provider names no engine concept, and
                // the registry is the one place allowed to narrow it.
                $app->make(Repository::class)->get('sqlens.audit.naming'),
                // …and the documentation policy, read here for the same reason: the two comment
                // rules share one judgment, and neither may reach for `config()` — this package
                // declares focused illuminate components rather than the framework, and the helper
                // belongs to the framework.
                $app->make(Repository::class)->get('sqlens.audit.documentation'),
                // The advisory reader, built ONCE here because it is the only place that knows both
                // the configuration and the application's base path — the two things its resolution
                // order needs. Handed down rather than reached for, like every other collaborator
                // above: a rule that read configuration would have a verdict its own tests cannot
                // see.
                new EolRepository($app->make(Repository::class), $app->basePath()),
                // Today, read ONCE per container rather than once per rule. A support window closes
                // on a date, and two rules reading the clock either side of midnight would give one
                // database two answers with nothing in the report to say which.
                date('Y-m-d'),
                // The privacy pack's COLUMN reading. Built here because this is the only place that
                // knows both the configuration and the application: discovering models means asking
                // the container where the application keeps its classes, and neither the rule
                // namespace nor the driver namespace may do that. Handed down, never reached for.
                self::privacyColumnEvaluator($app),
                // WHICH environment this run is looking at, built here for the same reason as the
                // advisory reader: it needs the application's configuration, and a rule reaching for
                // that would have a verdict its own tests cannot see.
                //
                // It was missing until 2026-08-23, and the slot below it was passed `null` — so the
                // three rules that judge a setting only on production could answer nothing but
                // `undetermined`, on every real run, for as long as they had shipped. Not a wrong
                // verdict: no verdict. Their unit suites pass because they construct the collaborator
                // the container never supplied.
                new RunEnvironment(
                    $app->make(Repository::class),
                    new ProductionConnectionDetector($app->make(Repository::class)),
                ),
            ),
        );

        // Bound rather than autowired: the refresher needs the SAME advisory reader the rules judge
        // from, plus the base path, and letting the container guess would hand it a second reader
        // with its own cache — a refresh could then write a file the run had already read past.
        $this->app->bind(
            AdvisoryRefresher::class,
            static fn (Application $app): AdvisoryRefresher => new AdvisoryRefresher(
                $app->make(Repository::class),
                new EolRepository($app->make(Repository::class), $app->basePath()),
                $app->basePath(),
                $app->make(Factory::class),
            ),
        );

        // The driver manager resolves a connection to a driver from config alone.
        // A singleton over the singleton registry, so a driver registered anywhere
        // is visible to every suite. Resolution reads config; it opens no connection.
        $this->app->singleton(
            DriverManager::class,
            static fn (Application $app): DriverManager => new DriverManager(
                $app->make(DriverRegistry::class),
                $app->make(Repository::class),
            ),
        );

        // The canonicalization seam, and a SINGLETON for the reason that makes it a seam
        // at all: `extend()` mutates the instance, so a third-party driver registering
        // its canonicalization and the factory asking for one have to be talking to the
        // same object. Bound per-resolution it would accept every registration and
        // remember none — which is what it did while it was not bound here at all.
        $this->app->singleton(
            CanonicalExtensionRegistry::class,
            static fn (Application $app): CanonicalExtensionRegistry => new CanonicalExtensionRegistry(
                $app->make(DriverManager::class),
            ),
        );

        // The external-tool machinery. The process runner is the real one; the known
        // set is EMPTY until an adapter (Squawk first) registers — the strict-tool
        // wiring is ready, with nothing yet to be strict about. Both are singletons so
        // a test can rebind them (a fake runner, a fake tool) for the whole run.
        // The one place a driver key is mapped to its catalog readers. It lives here, in the
        // composition root, rather than in src/Catalog: core must not import a driver, and a match
        // naming PgsqlCatalogReader would be exactly that coupling moved into a string.
        $this->app->singleton(CatalogReaderFactory::class, static function (): CatalogReaderFactory {
            $factory = new CatalogReaderFactory;

            $factory->register('pgsql', static function (Connection $connection, SessionBudget $budget, SubjectContext $context): CatalogReaders {
                // One session for both readers. The defense is engine-specific — how a session is
                // sealed read-only differs — which is why it is chosen here and not by the caller.
                $session = new ReaderSession($connection, new PgsqlSessionDefense, $budget);

                return new CatalogReaders(
                    new PgsqlCatalogReader($session, $context),
                    new PgsqlInstanceIdentityReader($session),
                    new PgsqlServerSettingsReader($session),
                    // The cross-fact collector, for the one question a setting rule cannot answer
                    // from its own subject: `ssl_min_protocol_version` keeps its configured value
                    // when `ssl` is off, so the minimum alone cannot say whether TLS runs at all.
                    new PgsqlSettingCrossFactCollector($session),
                    // The pooler reader takes the CONNECTION, not the session: transaction pooling
                    // is invisible inside a transaction, which is where the session always operates.
                    pooler: new PgsqlPoolerReader($connection, $budget),
                    // The security reader shares the session too. What a security reading sees depends
                    // on the ROLE it connects as, so a reading over a second connection could report a
                    // different server than the one the rest of the audit describes.
                    security: new PgsqlSecurityReader($session, Container::getInstance()->make('config')),
                    // The deploy suite's reader, over the SAME session for the same reason as the
                    // rest: one connection per run is a promise this package makes, and a sizes
                    // reading on a second one could describe a database nothing else looked at.
                    statistics: new PgsqlStatisticsReader($session),
                    // Same session again, and here the sharing is not a nicety: live activity is a
                    // property of the connection as much as of the server, so a reading on a second
                    // one could miss the very blocker this run is about.
                    activity: new PgsqlActivityReader($session),
                );
            });

            $factory->register('mysql', static function (Connection $connection, SessionBudget $budget, SubjectContext $context): CatalogReaders {
                $session = new ReaderSession($connection, new MysqlSessionDefense, $budget);

                return new CatalogReaders(
                    new MysqlCatalogReader($session, $context),
                    new MysqlInstanceIdentityReader($session),
                    new MysqlServerSettingsReader($session),
                    new MysqlSettingCrossFactCollector($session, (string) ($connection->getDatabaseName() ?: '')),
                    new MysqlPoolerReader($connection),
                    new MysqlSecurityReader($session),
                    new MysqlStatisticsReader($session),
                    new MysqlActivityReader($session),
                );
            });

            return $factory;
        });

        // The project's own composer.json, for the packages it declares — the most direct statement
        // a project can make that it is multi-tenant. It is bound in its own right rather than
        // built inside the runner closure below, because BOTH resolution paths have to get it: the
        // command resolves the `AuditRuns` seam, and several tests resolve the concrete
        // `AuditRunner`. A scalar constructor argument would break the second path's reflection
        // auto-resolution, so the path this package injects is the object that carries it.
        //
        // The root comes from the container for the same reason the driver registry's does: this
        // package must not call `base_path()` — a Foundation helper it does not depend on — and the
        // container is where the path is known.
        $this->app->singleton(
            ProjectManifest::class,
            static fn (Application $app): ProjectManifest => new ProjectManifest($app->basePath()),
        );

        // What `sqlens:audit` actually runs. Bound here so the command depends on the seam and
        // never on the pipeline.
        $this->app->singleton(AuditRuns::class, AuditRunner::class);
        // The lint half's seam, added when the security run needed to call both halves and could
        // test only one: LintRunner is final readonly, so a caller depending on the class could not
        // be driven without a database.
        $this->app->singleton(LintRuns::class, LintRunner::class);
        // The injection half, and it is bound EXPLICITLY rather than left to autowiring — which is
        // the whole reason this binding exists. `SecurityRunner` takes it as `?AnalyseBridge = null`,
        // and the container answers an unresolvable optional dependency with the default instead of
        // an error: without this line the bridge would never be built, the half would report "nothing
        // wired me", and every arm would stay green. A silent `null` is exactly the failure this
        // package refuses everywhere else.
        $this->app->bind(AnalyseBridge::class, static function (Application $app): AnalyseBridge {
            /** @var Repository $config */
            $config = $app->make('config');

            $mode = $config->get('sqlens.security.analyse.mode');
            $path = $config->get('sqlens.security.analyse.result_path');

            return new AnalyseBridge(
                // An unreadable mode is `off`, never a crash and never `read`. The config schema
                // reports the bad value as its own finding; a run must not die on the way there.
                is_string($mode) ? AnalyseMode::tryFrom($mode) ?? AnalyseMode::Off : AnalyseMode::Off,
                is_string($path) ? $path : null,
                (string) $app->basePath(),
            );
        });
        // The deploy half's seam, and it exists for the reason the lint one does: a second caller —
        // the MCP `predeploy` tool — needs the same verdict, and a second composition of the seven
        // services it holds would be a second predeploy with its own answer about whether a deploy
        // may proceed.
        //
        // `bind`, not `singleton`, and that was measured rather than chosen: a singleton captures
        // its dependencies once, so a caller that swaps one afterwards — which is exactly how the
        // session-bounds arms prove a header stays silent rather than optimistic — would still be
        // driving the old one. The command used to resolve them per `handle()` call, and this keeps
        // that.
        $this->app->bind(PreflightRuns::class, PreflightService::class);

        // The escalation table, built ONCE per run from the shipped artefact plus whatever the
        // project overrode. A singleton because `load()` reads a file and parses it, and because two
        // instances would be two answers to "when is a rewrite critical" — free to differ the moment
        // somebody passes a path in one place and not the other.
        //
        // An unknown operation name throws out of here rather than being dropped. That is deliberate
        // and it is the whole reason the key is declared at all: a threshold a project set that
        // silently never applies is the no-op this package exists to refuse.
        $this->app->singleton(
            SeverityEscalator::class,
            static function (Application $app): SeverityEscalator {
                $overrides = $app->make('config')->get('sqlens.preflight.thresholds');
                $keyed = [];

                foreach (is_array($overrides) ? $overrides : [] as $operation => $steps) {
                    $keyed[(string) $operation] = $steps;
                }

                return new SeverityEscalator(EscalationThresholds::load($keyed));
            },
        );
        // Who may start a database-creating run. Bound as a seam because TWO callers ask — the lint
        // command and the MCP shadow tool — and a second gathering of the guard's inputs would be a
        // second answer to "which environments are allowed", free to drift toward permissive.
        // What this build exposes as tools. Bound rather than called statically wherever it is
        // needed, because the two lists it is compared against — the configuration surface and this
        // one — only differ in a window that a test has to be able to create.
        $this->app->singleton(ToolRegistry::class, static fn (): ToolRegistry => ToolRegistry::declared());

        $this->app->singleton(
            ShadowClearance::class,
            static fn (Application $app): ShadowClearance => new ApplicationShadowClearance($app, $app->make('config')),
        );

        $this->app->bind(
            // The pending set, assembled where the database classes belong. A consumer of this
            // contract — `sqlens:drift` today — then names no Illuminate\Database class of its own,
            // which is what lets the core-purity guard prove that a command reads through the sealed
            // reader and nowhere else.
            //
            // The paths come from the ONE shared resolver rather than from a second reading: the
            // lint layer and this one having different ideas of what a migration path is would make
            // a drift comparison's expectation side a different migration state than the one lint
            // reports on.
            PendingResolver::class,
            static fn (Application $app): PendingResolver => new PendingMigrationResolver(
                $app->make(DatabaseManager::class),
                $app->make(Migrator::class),
                new MigrationPaths($app, $app->make(Migrator::class), $app->make('config'))->all(),
                'migrations',
                (string) $app->basePath(),
            ),
        );

        $this->app->singleton(ProcessRunner::class, SystemProcessRunner::class);
        // The tool is registered NOW, and not a commit earlier, because registration is what makes
        // a run on a machine without it report a missing tool — naming, in whatItEnables(), the
        // rules it would add. Until the chain below existed, that report named rules that did not
        // exist: a promise with nothing behind it.
        // Both amplifiers are KNOWN from here on, which is what makes every PostgreSQL run report
        // one that is missing.
        //
        // Asked of the DRIVERS rather than listed here, and the difference is a package boundary.
        // This line used to read `new KnownTools([new SquawkTool, new PglsTool])`, which made the
        // composition root the only place that knew a PostgreSQL-only tool existed. This package promises
        // the split into a core plus two driver packages stays a mechanical move — and under it
        // those two classes ship with the PostgreSQL package, so a core provider naming them would
        // reference classes it cannot autoload. Now a driver package brings its own adapters, which
        // is what the extension seam was for.
        $this->app->singleton(KnownTools::class, static fn (Application $app): KnownTools => new KnownTools(
            array_values(array_merge([], ...array_map(
                static fn (Driver $driver): array => [...$driver->tools()],
                $app->make(DriverRegistry::class)->all(),
            ))),
        ));

        // What can ACT on a tool's output — a separate list on purpose, because a tool is worth
        // reporting as missing long before anything can use it. See ToolContributions.
        $this->app->singleton(ToolContributions::class, static fn (Application $app): ToolContributions => new ToolContributions([
            new PglsContribution(
                new PglsRunner($app->make(ProcessRunner::class), dirname(__DIR__)),
                new PglsFindingMapper(PglsRuleMap::bundled()),
                PglsRuleMap::bundled(),
                $app->make(Repository::class),
            ),
        ]));

        // The whole adapter chain, assembled in one place. The order is load-bearing and the
        // guarantees only hold end to end, so the runner is handed the finished thing rather than
        // six collaborators to wire in the right sequence.
        $this->app->singleton(SquawkContribution::class, function (Application $app): SquawkContribution {
            $map = SquawkRuleMap::bundled();
            $version = $map->measuredAgainst;

            /** @var Repository $config */
            $config = $app->make(Repository::class);
            $timeout = $config->get('sqlens.tools.squawk.timeout');

            return new SquawkContribution(
                new SquawkRunner($app->make(ProcessRunner::class)),
                new SquawkFindingMapper($map, $app->basePath()),
                new SquawkDeduplicator($map, $version),
                new ToolPositionMapper,
                // A bound the project set, or the shipped default. Never unbounded: an amplifier
                // that hangs must cost a named undetermined, not the lint run it was helping.
                is_int($timeout) && $timeout > 0 ? (float) $timeout : SquawkContribution::DEFAULT_TIMEOUT_SECONDS,
                $config->get('sqlens.tools.squawk.fast_path') === true,
            );
        });
    }

    public function boot(): void
    {
        // SQLens is stateless: it owns no table, no HTTP route, and no view, so the
        // provider loads none. This is not just tidiness — with no bundled migration
        // the package cannot, by construction, create a table in a host database
        // (primum non nocere). Only the translations ship.
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'sqlens');

        $this->armGuard();

        if ($this->app->runningInConsole()) {
            // The runner is bound with an EMPTY registry, deliberately. Checks arrive in their own
            // changes and register themselves here; a runner that discovered them would iterate in
            // whatever order the container built, and two runs against an unchanged database would
            // report the same findings in a different sequence — which a diff reads as a change.
            $this->app->bind(SessionDefenses::class, DriverRegistry::class);

            // The run header reads the session bounds back through this seam, and the command
            // takes the INTERFACE — so a test can substitute a reader that refuses, which is the
            // only way the header's silent-rather-than-optimistic path can be proved. The check
            // itself is `final readonly` and cannot be doubled.
            // Registered with an EMPTY check list, deliberately, and it is not a placeholder: a
            // verifier that checked nothing must still be a complete, honest run — it reports what
            // it ran (nothing), exits clean, and does not claim to have verified anything. The
            // post-deploy checks are hung on it one ticket at a time, and until then the command is
            // the shell being proved rather than the checks.
            $this->app->singleton(PostdeployVerifier::class, static fn (Application $app): PostdeployVerifier => new PostdeployVerifier([
                // The post-deploy registry. Each entry ADAPTS a check that already owns its catalog
                // reading — never a second implementation of one, because the same catalog
                // answering differently depending on which command asked is the determinism break
                // this package treats as a defect.
                new PostdeployInvalidIndexCheck,
                new PostdeployNotValidConstraintCheck,
                // …and the one that owns its own reading, because there is no predeploy twin to
                // adapt: what a NAME suggests is a question only worth asking after the deploy,
                // when the objects it left behind exist. Its pattern list is built here for the
                // reason every other policy is — a check that read configuration would have a
                // verdict its own tests cannot see.
                new OrphanTransitionObjectCheck(
                    TransitionObjectPatterns::fromConfig(
                        $app->make(Repository::class)->get('sqlens.deploy.postdeploy.transition_patterns'),
                    ),
                ),
                // The MySQL side. Both entries are registered unconditionally and each declares the
                // driver it answers for — the verifier asks, so a run against PostgreSQL never sees
                // these and a run against MySQL never sees the PostgreSQL ones.
                new MysqlOrphanTransitionObjectCheck,
                // …and the one that exists to answer NOT APPLICABLE out loud. A missing check and a
                // clean result print the same on this engine, and a reader comparing two databases
                // is exactly who would be misled by that.
                new MysqlInvalidIndexCheck,
                // The MySQL counterpart to PostgreSQL's NOT VALID constraint — a different catalog
                // semantic, not a second spelling of the same one, so it shares no line with it.
                new UnenforcedConstraintCheck,
            ]));

            // The formatter registry. An explicit LIST rather than discovery, for the reason the
            // deploy registries state: an order that depended on which adapter registered first
            // would make two identical projects format differently, and the output is committed.
            $this->app->singleton(FormatterRegistry::class, static function (Application $app): FormatterRegistry {
                $settings = FormatConfig::from($app->make(Repository::class));

                // WRAPPED, and the wrapper is the whole reason a repository-wide run is affordable.
                // Both external backends resolve their binary and probe its version inside
                // `format()`, so an unwrapped runner paid a `$PATH` walk AND a process spawn for
                // every `.sql` file — measured at 25 of each for 25 files. Neither answer can change
                // between two files of one run. See MemoizingProcessRunner.
                //
                // One wrapper for BOTH backends on purpose: they are different binaries, the cache
                // is keyed by name, and sharing it means a run that falls back from one to the other
                // does not re-ask about the first.
                $processes = new MemoizingProcessRunner($app->make(ProcessRunner::class));

                // A backend this project switched off is not REGISTERED, rather than registered
                // and skipped later. That keeps `auto` honest for free: an absent candidate never
                // reaches the passed-over list, so a decision is never reported as a loss and strict
                // tool mode never fails over it. The names travel separately so a NAMED disabled
                // backend can still be refused with the true reason.
                $backends = [];

                if (! in_array('pgformatter', $settings->disabledBackends, true)) {
                    $backends[] = new PgFormatterBackend($processes, $settings->pgFormatterPath ?? 'pg_format', $settings->timeout);
                }

                if (! in_array('sqlfluff', $settings->disabledBackends, true)) {
                    $backends[] = new SqlFluffBackend($processes, $settings->sqlFluffPath ?? 'sqlfluff', $settings->timeout);
                }

                // Last, and always present — and never switchable off. The two above are better at
                // the job and are not installed on the machine of somebody who just ran
                // `composer require`; this one is what makes `sqlens:format` work with no binaries
                // at all, so a project that could turn it off could turn the suite into nothing.
                $backends[] = new PhpSqlFormatter;

                return new FormatterRegistry($backends, $settings->disabledBackends);
            });

            $this->app->singleton(DialectResolver::class, static fn (Application $app): DialectResolver => new DialectResolver($app->make(Repository::class)));

            // Built rather than auto-resolved: the check needs its driver capabilities, and a
            // container-constructed one would get an empty map and throw for every engine. The
            // capabilities are the same two the preflight runner is given below — named here
            // because this provider is the composition root.
            $this->app->bind(ReadsSessionBounds::class, static fn (): SessionDefenseAppliedCheck => new SessionDefenseAppliedCheck([
                'pgsql' => new PgsqlSessionDefenseState,
                'mysql' => new MysqlSessionDefenseState,
            ]));

            // The MCP conversation loop, bound rather than constructed in the command so a test can
            // put a double in its place — the real one takes over this process's STDIN, which no
            // in-process test can hand over and get back.
            $this->app->bind(ServesMcp::class, StdioServerLoop::class);

            // One shield per process, and it goes up NOW when this run is the MCP server.
            //
            // Reading argv rather than waiting for the command to run, because a foreign service
            // provider's `boot()` is exactly the output this exists to catch and it happens before
            // any command handles anything. Providers registered before this one can still slip a
            // line out — that is the honest limit of doing it from inside the container, and it is
            // why the subprocess arm reads the whole stream rather than trusting the mechanism.
            $this->app->singleton(StdoutShield::class);

            $this->app->make(StdoutShield::class)->engageIfWanted(
                array_values(array_filter(is_array($_SERVER['argv'] ?? null) ? $_SERVER['argv'] : [], is_string(...))),
            );

            // The SDK's own provider, registered explicitly when the package is installed.
            //
            // It is NOT decoration: that provider installs a container `resolving` callback which
            // is the only thing that fills a tool's Request with the arguments a client sent.
            // Without it every `tools/call` reaches its tool with an EMPTY request — measured, and
            // the shape of the failure is the worst kind: a perfectly good call comes back
            // "rule_id is required", and a tool that did not validate would simply run with no
            // parameters at all.
            //
            // In an ordinary application Laravel's package discovery has already registered it and
            // this call is a no-op. It exists for the applications where discovery is off or the
            // provider list is explicit — where the server would otherwise be quietly deaf.
            if (class_exists(McpServiceProvider::class)) {
                $this->app->register(McpServiceProvider::class);
            }

            $this->app->singleton(PreflightRunner::class, static function (Application $app): PreflightRunner {
                /** @var Repository $config */
                $config = $app->make('config');
                $pin = $config->get('sqlens.assume_server_version');

                // The order is DECLARED here and nowhere else. Two runs against an unchanged database
                // must produce byte-identical reports, and a registry the container discovered would
                // iterate in whatever order it happened to build.
                //
                // Context-truth first, and that is not alphabetical: every later check reasons about a
                // server, and a run whose version is wrong has already answered every one of them
                // against the wrong world.
                return new PreflightRunner([
                    new ServerVersionSkewCheck(is_string($pin) ? $pin : null),
                    // Second, and after the version rather than before it for a reason: a run whose
                    // version is wrong has already answered every later question against the wrong
                    // world, so context truth comes first. Within context truth, "can this instance
                    // accept writes at all" decides whether the deploy can happen — everything
                    // after it is about how badly it might go.
                    new ReadOnlyTargetCheck([
                        // The composition root names both engines, which is what a composition root
                        // is for. The check itself no longer can — see ReadsWriteAcceptance.
                        'pgsql' => new PgsqlWriteAcceptance,
                        'mysql' => new MysqlWriteAcceptance,
                    ]),
                    // Third, and last among the context checks. It answers a question about THIS
                    // RUN rather than about the database, so it belongs after the two that decide
                    // whether the run means anything at all — but before any check that reasons
                    // about load, because those are the ones a missing timeout would let hang.
                    new SessionDefenseAppliedCheck([
                        'pgsql' => new PgsqlSessionDefenseState,
                        'mysql' => new MysqlSessionDefenseState,
                    ]),
                    // Fourth, and deliberately AFTER the session defense rather than beside the
                    // other context checks: this one reads ~400 rows from `pg_settings`, which is
                    // the first thing in the run that could hang, and the check before it is the
                    // one that establishes there is a bound on hanging.
                    //
                    // Driver-specific, and that is why it is named here. The runner asks
                    // `appliesTo()` before running anything, so a MySQL target skips it without
                    // opening a session for it — and this provider is the composition root, the one
                    // place allowed to know both engines by name.
                    new ServerSettingsCheck,
                    // The MySQL half of the same question. Two classes rather than one with a
                    // `match`, because they share almost no substance: different hazards, different
                    // shipped defaults, and different ways of withholding a value. Only one of them
                    // ever runs — `appliesTo()` decides before either opens anything.
                    new MysqlServerSettingsCheck,
                    // Last among the context checks, and last for a reason: it reads the index
                    // catalog, which is the widest read in the registry. Everything that decides
                    // whether the run means anything at all has already answered by here.
                    new InvalidIndexCheck,
                    // Beside it, and for the same reason: both answer "is there wreckage from last
                    // time", both read only the catalog, and neither can be answered from the
                    // instance state the earlier checks look at.
                    new NotValidConstraintCheck,
                    // Last, and the only one that reads LIVE state rather than the catalog: a lag
                    // measured before the slower questions would be a lag from a moment that has
                    // already passed by the time the report is written.
                    new ReplicationLagCheck,
                    // Last of all, and the only one that needs BOTH halves of the run: the pending
                    // migrations to know which locks are coming, and the live activity to know what
                    // holds them. It runs after everything that could refuse the run outright.
                    new LockBlockerCheck,
                    // Its MySQL counterpart. Same question, different lock vocabulary — and a
                    // different way of going quiet: `performance_schema` can be off, and an empty
                    // reading then means nothing rather than nothing-found.
                    new MetadataLockCheck,
                    // Immediately BEFORE the headroom question, because it answers the half of it
                    // a managed database cannot: free capacity is not exposed there, so
                    // `DiskHeadroomCheck` reports undetermined on most instances — and a retained
                    // slot is the commonest reason the answer would have been no, visible from
                    // inside the database.
                    new ReplicationSlotCheck,
                    // Last, and driver-neutral: it asks about SIZE, and both engines answer that
                    // through the same reader. It runs after the lock checks because a deploy that
                    // cannot start is a more urgent thing to hear about than one that might fill up.
                    // The operator's own headroom figure is injected rather than read inside the
                    // check, for the reason every other policy is: a check that read configuration
                    // would carry a verdict its own tests cannot see.
                    new DiskHeadroomCheck(self::declaredDiskBytes($app)),
                    // Last, and the most consequential when it fires: a role that may not do what
                    // the migration asks stops `migrate --force` HALFWAY, with the application
                    // already deployed against the other half.
                    new GrantCheck,
                    // Its MySQL counterpart. Same question, and an asymmetric answer: PostgreSQL can
                    // resolve another role's inheritance, MySQL cannot — so that one withholds a
                    // finding where this one emits it.
                    new MysqlGrantCheck,
                ]);
            });

            // `sqlens:mcp` is registered unconditionally, and that is deliberate rather than an
            // oversight. Its SDK is a `suggest`, so it may genuinely be absent — and a command
            // that hid itself in that case would leave an operator typing a name that does not
            // exist, with nothing to read. Registered, it answers with the reason and the one
            // command that fixes it. Registration itself touches nothing the SDK provides.
            $this->commands([DoctorCommand::class, LintCommand::class, AuditCommand::class, SecurityCommand::class, BaselineCommand::class, PredeployCommand::class, PostdeployCommand::class, DriftCommand::class, FormatCommand::class, McpCommand::class, AgentRulesCommand::class]);
            $this->registerPublishing();
        }
    }

    private function registerPublishing(): void
    {
        // Resolve publish targets through the Application contract's path methods
        // (available via illuminate/contracts), NOT the config_path()/lang_path()
        // global helpers. Those are Foundation helpers, shipped ONLY with
        // laravel/framework — which this lean package does not require — so the
        // helper form would freeze a wrong dependency contract and fatal in a
        // non-Foundation host. The method form is behavior-identical.
        //
        // Each group carries the bare 'sqlens' umbrella tag on top of its specific
        // one, so `vendor:publish --tag="sqlens"` publishes every resource at once —
        // the tag convention Laravel's official package skeleton establishes. A
        // stateless package publishes only its config and its translations.
        $this->publishes([
            __DIR__.'/../config/sqlens.php' => $this->app->configPath('sqlens.php'),
        ], ['sqlens', 'sqlens-config']);

        $this->publishes([
            __DIR__.'/../lang' => $this->app->langPath('vendor/sqlens'),
        ], ['sqlens', 'sqlens-lang']);
    }

    /**
     * The operator's free-space CLAIM, or null when they made none.
     *
     * A method rather than a ternary at the call site, and for a reason that is about the compiler
     * rather than about style: the `: null` arm is a literal, so it carries no runtime opcode and a
     * line-based coverage driver reports it as never executed however many tests take it. Measured
     * here, and the same mechanism as the folded string in `TimeBudgetNotice` — an unmeasurable line
     * under a 100% floor is a floor that cannot be met.
     *
     * Not a cast, either. `'50GB'` casts to fifty BYTES, which would report a nearly full disk on a
     * healthy volume; a value that is not an integer is a claim this check does not have.
     */
    private static function declaredDiskBytes(Application $app): ?int
    {
        $declared = $app->make(Repository::class)->get('sqlens.deploy.predeploy.available_disk_bytes');

        if (is_int($declared)) {
            return $declared;
        }

        return null;
    }

    /**
     * The application's Eloquent models, discovered the way `model:prune` discovers them.
     *
     * Resolved HERE rather than inside the discovery, because this is the one place that has the
     * application: `getNamespace()` is on the Foundation contract, and the app directory is the
     * container's own `path` binding. Handing both down keeps the discovery a plain value object
     * that a test can point at any directory.
     *
     * @return list<class-string<Model>>
     */
    private static function discoveredModels(Application $app): array
    {
        $root = $app->make('path');

        return new ModelDiscovery(is_string($root) ? $root : '', $app->getNamespace())->models();
    }

    /**
     * The privacy pack's column reading, or null when the pack is off.
     *
     * Null is not a silent pass: the rule turns an absent reading into a named `undetermined`. It is
     * returned when the pack is switched off because the rule is then not admitted at all, and
     * paying for a filesystem walk and a dictionary read on every container boot to feed a rule
     * nothing will ask is the kind of cost nobody notices and everybody carries.
     *
     * A dictionary this project cannot read is deliberately NOT swallowed — {@see PrivacyDictionary}
     * throws, and a pack whose dictionary is broken must fail loudly rather than match nothing.
     */
    private static function privacyColumnEvaluator(Application $app): ?UnencryptedColumnEvaluator
    {
        $pack = new PrivacyPack($app->make(Repository::class));

        if (! $pack->isEnabled()) {
            return null;
        }

        $path = $pack->dictionaryPath();

        return new UnencryptedColumnEvaluator(
            $path === null
                ? PrivacyDictionary::bundled($pack->extraTerms())
                : PrivacyDictionary::fromFile(
                    $app->basePath(ltrim($path, DIRECTORY_SEPARATOR)),
                    $pack->extraTerms(),
                ),
            new ModelCastReader(self::discoveredModels($app)),
            $pack->ignoredColumns(),
        );
    }

    /**
     * The guard suite, armed from configuration and from nothing else.
     *
     * ## The early exit is the feature
     *
     * With `sqlens.guard.profile` null this method reads one config key and returns. No manager is
     * built, no logger is resolved, no listener is registered, and nothing is bound into the
     * container. "Disabled" has to mean ABSENT rather than cheap — a safety feature that costs a
     * closure on every query while switched off is a performance ticket waiting to happen, and the
     * no-op arm in the test suite is what keeps that honest.
     *
     * ## In `boot()`, after the config merge, and not in `register()`
     *
     * A strictness switch set during registration reads the package defaults rather than the
     * project's, because the published config has not been merged yet. The failure is silent and
     * looks like a profile that does not work.
     *
     * ## An unknown profile name is an exception, and it happens HERE
     *
     * Deliberately at boot rather than at the first query: a name nothing defines would otherwise
     * disable every guardrail in the application while the configuration still reads as though they
     * are on, and nothing would ever say so.
     */
    private function armGuard(): void
    {
        $config = $this->app->make(Repository::class);

        /** @var array<string, mixed> $guard */
        $guard = is_array($declared = $config->get('sqlens.guard')) ? $declared : [];

        // ONE null gate, and it is the resolver's. An earlier `if (($guard['profile'] ?? null) ===
        // null) return;` stood here as well, which read as defensive and was the opposite: it made
        // the resolver's own null unreachable from this method, so the branch below could never run
        // and the 100% floor reported it — correctly — as a line no test can reach. Two gates on one
        // condition means one of them is always dead.
        //
        // What the early return bought was skipping two config reads on a boot with no guardrail.
        // That is `database.connections` and `logging.channels`, both already resolved by the time
        // any provider boots, and it is not worth a branch nothing can enter.
        $profile = GuardProfile::resolve(
            $guard,
            array_map(strval(...), array_keys(is_array($connections = $config->get('database.connections')) ? $connections : [])),
            array_map(strval(...), array_keys(is_array($channels = $config->get('logging.channels')) ? $channels : [])),
        );

        // No profile named: every guardrail is off, which is the default and the common case.
        // Everything below — the logger, the manager, the inspectors — exists only because a
        // profile was named.
        if (! $profile instanceof GuardProfile) {
            return;
        }

        // The channel is resolved ONCE, here, where its existence has just been validated. Handing
        // the logger a PSR-3 instance rather than a channel name is what keeps `ViolationLogger`
        // free of Laravel's logging package entirely.
        $logger = new ViolationLogger($this->app->make('log')->channel($profile->logChannel));

        $armed = new GuardManager([
            new StrictModeGuard($logger),
            // ONE listener for all three query-based guardrails. A listener each would be three
            // closures on the hot path of every query an application runs.
            new QueryWatcher($this->app->make(Dispatcher::class), [
                new SlowQueryGuard($logger),
                new RuntimeDdlGuard($logger, $this->app->runningInConsole()),
                new UnboundRawSqlGuard($logger),
            ]),
        ])->arm($profile);

        // Bound AFTER arming and only when something was armed, so a test can ask what happened
        // without the answer being "an empty manager exists".
        $this->app->instance('sqlens.guard.armed', $armed);
    }
}
