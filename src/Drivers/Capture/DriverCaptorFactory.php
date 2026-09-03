<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Capture;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Migrations\Migrator;
use Pushery\SQLens\Canonical\Extensions\CanonicalExtensionRegistry;
use Pushery\SQLens\Canonical\Stages\StatementSplitter;
use Pushery\SQLens\Capture\CanonicalizingCaptorDecorator;
use Pushery\SQLens\Capture\MigrationLoader;
use Pushery\SQLens\Capture\MigrationPaths;
use Pushery\SQLens\Capture\PreScan\PreScanGate;
use Pushery\SQLens\Capture\PretendCaptor;
use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Capture\Shadow\ShadowCaptor;
use Pushery\SQLens\Capture\Shadow\ShadowDatabaseName;
use Pushery\SQLens\Capture\Shadow\ShadowMigrationRunner;
use Pushery\SQLens\Capture\Shadow\ShadowNoiseFilter;
use Pushery\SQLens\Capture\Shadow\ShadowOrphanSweeper;
use Pushery\SQLens\Capture\Shadow\ShadowSessionDefense;
use Pushery\SQLens\Capture\Shadow\ShadowTargetIdentity;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Contracts\BindingFormatter;
use Pushery\SQLens\Contracts\Captor;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Contracts\ReplicaProbe;
use Pushery\SQLens\Contracts\ShadowProvisioner;
use Pushery\SQLens\Deploy\Drift\ShadowReferenceBuilder;
use Pushery\SQLens\Drivers\DriverManager;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\Mysql\Capture\MysqlBindingFormatter;
use Pushery\SQLens\Drivers\Mysql\Shadow\ConnectionMysqlMaintenanceGateway;
use Pushery\SQLens\Drivers\Mysql\Shadow\MysqlReplicaProbe;
use Pushery\SQLens\Drivers\Mysql\Shadow\MysqlSchemaDumpReader;
use Pushery\SQLens\Drivers\Mysql\Shadow\MysqlShadowProvisioner;
use Pushery\SQLens\Drivers\Pgsql\Capture\PgsqlBindingFormatter;
use Pushery\SQLens\Drivers\Pgsql\Shadow\ConnectionMaintenanceGateway;
use Pushery\SQLens\Drivers\Pgsql\Shadow\PgsqlPoolerProbe;
use Pushery\SQLens\Drivers\Pgsql\Shadow\PgsqlReplicaProbe;
use Pushery\SQLens\Drivers\Pgsql\Shadow\PgsqlShadowProvisioner;
use Pushery\SQLens\Drivers\Pgsql\Shadow\PgsqlVirginTemplateBuilder;
use Pushery\SQLens\Rules\StabilityGate;
use Pushery\SQLens\Security\PathBinding;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The composition root that turns a resolved connection into a fully wired captor —
 * the ONE place capture meets the concrete drivers, kept out of the console and
 * capture namespaces so both stay free of a driver import (the split insurance).
 *
 * It lives under `Drivers\` precisely because it must name both engines: it maps a
 * driver key to that engine's canonicalization and binding formatter, then assembles
 * the standard chain — a `PretendCaptor` wrapped in the canonicalizing decorator so
 * every statement reaches a rule in canonical form, wrapped again in the pre-scan
 * gate so a migration with an unseeable side effect is held out of the run. A driver
 * the factory has no capture wiring for is a NAMED failure, never a silent skip —
 * `DriverManager` already refused the unsupported engines, so this only guards the
 * gap where a driver is known but its capture pieces are not registered yet.
 *
 * The canonicalization is deliberately mapped the same way `CanonicalExtensionRegistry`
 * maps it (the third-party extension seam); the binding formatter has no registry of
 * its own yet, so the built-in pair is mapped here until one exists.
 */
final readonly class DriverCaptorFactory
{
    /** The lowest age a shadow database may be swept at, in seconds — see orphanThresholdSeconds(). */
    private const int ORPHAN_THRESHOLD_FLOOR = 3600;

    public function __construct(
        private DriverManager $drivers,
        private CanonicalExtensionRegistry $extensions,
        private DatabaseManager $database,
        private Repository $config,
        private Application $app,
    ) {}

    /**
     * The pretend-mode captor for a connection, or the named reason the driver
     * cannot be captured. Pretend collects the migration's SQL via Laravel's
     * `--pretend` without executing it — the default, do-no-harm mode.
     */
    public function pretend(string $connectionName): Captor|DriverResolutionFailure
    {
        $driver = $this->drivers->resolve($connectionName);

        if ($driver instanceof DriverResolutionFailure) {
            return $driver;
        }

        $key = $driver->key();
        $canonicalization = $this->canonicalizationFor($key);
        $formatter = $this->formatterFor($key);

        // A driver the manager supports but this factory has no capture wiring for is
        // an honest named failure — the alternative is a run that captures nothing and
        // reads as clean.
        if (! $canonicalization instanceof DriverCanonicalization || ! $formatter instanceof BindingFormatter) {
            return DriverResolutionFailure::unknownDriver($key);
        }

        // ONE loader for both the forward capture and the rollback read: a migration file is
        // loaded at most once per run, because a second load of a named-class migration is an
        // uncatchable fatal. See MigrationLoader.
        $loader = new MigrationLoader;

        return $this->gateOver(
            $this->pretendChain($connectionName, $canonicalization, $formatter, $key, $loader),
            $connectionName,
            $canonicalization,
            $formatter,
            $key,
            $loader,
        );
    }

    /**
     * The EXPECTATION-side builder for a drift comparison, assembled from the same parts the shadow
     * captor uses.
     *
     * It exists because those parts were assembled privately and nothing outside this class could
     * reach them — so the reference builder had no way to be constructed, and a mechanism that
     * cannot be constructed is a mechanism that never runs.
     *
     * The two reader factories are PARAMETERS rather than pulled from the container, though this
     * class holds one. A dependency taken from the container is invisible in the signature and
     * unmockable at the seam; passing them keeps both properties, and the caller already holds them
     * because it reads the live side of the comparison through the same two.
     *
     * Assembling this touches no database — the same promise `shadow()` above makes, and for the
     * same reason: a blocked guard decision must be able to end a run before anything exists to
     * clean up.
     */
    public function shadowReference(
        string $connectionName,
        ReaderConnectionFactory $connections,
        CatalogReaderFactory $readers,
    ): ShadowReferenceBuilder|DriverResolutionFailure {
        $driver = $this->drivers->resolve($connectionName);

        if ($driver instanceof DriverResolutionFailure) {
            return $driver;
        }

        $key = $driver->key();

        return new ShadowReferenceBuilder(
            $this->provisionerFor($key, $connectionName),
            new ShadowMigrationRunner(
                $this->database,
                new ShadowNoiseFilter,
                $this->migrationsTable(),
                new ShadowSessionDefense($this->shadowTimeout()),
            ),
            $connections,
            $readers,
            $connectionName,
            $this->databaseName($connectionName),
            $key,
            $this->config->get('sqlens.capture.shadow.keep_on_failure') === true,
        );
    }

    /**
     * The shadow-mode captor for a connection: the migrations run FOR REAL against a
     * throwaway database and the SQL is read off the wire, then flows through exactly
     * the same canonicalization and pre-scan chain as pretend. One data path, two
     * sources — never a second engine.
     *
     * The guard decision is a parameter rather than something this method works out,
     * so there is exactly one guard in the system and the captor is handed its verdict.
     * A blocked decision builds no provisioner at all — belt and braces, since the
     * provisioner creates nothing until `provision()` runs and the captor never calls
     * it on a blocked decision. Assembling this object touches no database.
     */
    public function shadow(string $connectionName, GuardDecision $decision, bool $roundtrip = false): Captor|DriverResolutionFailure
    {
        $driver = $this->drivers->resolve($connectionName);

        if ($driver instanceof DriverResolutionFailure) {
            return $driver;
        }

        $key = $driver->key();
        $canonicalization = $this->canonicalizationFor($key);
        $formatter = $this->formatterFor($key);

        if (! $canonicalization instanceof DriverCanonicalization || ! $formatter instanceof BindingFormatter) {
            return DriverResolutionFailure::unknownDriver($key);
        }

        $runner = new ShadowMigrationRunner(
            $this->database,
            new ShadowNoiseFilter,
            $this->migrationsTable(),
            new ShadowSessionDefense($this->shadowTimeout()),
        );

        $inner = new ShadowCaptor(
            $decision,
            // Only an ALLOWED decision builds a provisioner — see the note above.
            $decision->isBlocked() ? null : $this->provisionerFor($key, $connectionName),
            $runner,
            $this->config->get('sqlens.capture.shadow.keep_on_failure') === true,
            $this->replicaProbeFor($key),
            $connectionName,
            $key === 'pgsql' ? new PgsqlPoolerProbe($this->database) : null,
            is_string($this->config->get('sqlens.capture.shadow.direct_connection')),
            $this->directConnectionIsElsewhere($connectionName),
            $roundtrip,
            $this->sweeperFor($key, $connectionName),
        );

        return $this->gateOver(
            CanonicalizingCaptorDecorator::forDriver($inner, $canonicalization, $formatter, $this->subjectContextFor($key)),
            $connectionName,
            $canonicalization,
            $formatter,
            $key,
            new MigrationLoader,
        );
    }

    /**
     * The canonicalizing pretend chain for a connection — a `PretendCaptor` wrapped so every
     * statement it collects reaches a rule in canonical form.
     *
     * Named once because it is built twice: as the capture itself in pretend mode, and as the
     * ROLLBACK reader in every mode (see {@see gateOver()}). Two constructions of the same
     * chain would be two chances for the rollback leg to be canonicalized differently from the
     * statements it is compared against, which is the one thing that must not differ.
     */
    private function pretendChain(
        string $connectionName,
        DriverCanonicalization $canonicalization,
        BindingFormatter $formatter,
        string $key,
        MigrationLoader $loader,
    ): Captor {
        return CanonicalizingCaptorDecorator::forDriver(
            new PretendCaptor($this->database->connection($connectionName), $loader),
            $canonicalization,
            $formatter,
            $this->subjectContextFor($key),
        );
    }

    /**
     * The pre-scan gate over a captor, with the rollback reader attached.
     *
     * The reader is a PRETEND chain whatever mode the run is in — shadow included. What a rule
     * about `down()` needs is the SQL the rollback WOULD emit, and pretend is the only way to
     * learn that without running the one migration method whose job is to destroy things.
     * Building it here, in the composition root, keeps both modes on one reading of the
     * rollback rather than a fast one and a real one that could disagree.
     */
    private function gateOver(
        Captor $inner,
        string $connectionName,
        DriverCanonicalization $canonicalization,
        BindingFormatter $formatter,
        string $key,
        MigrationLoader $loader,
    ): PreScanGate {
        return PreScanGate::withDefaultDetectors(
            $inner,
            $this->stringList('sqlens.capture.prescan.side_effects.additional'),
            $this->stringList('sqlens.capture.prescan.indirect_calls.allowlist'),
            $this->pretendChain($connectionName, $canonicalization, $formatter, $key, $loader),
            // The same gate the rule registry goes through, read from the same key. Passed rather
            // than applied downstream so there is ONE filter: a second one beside the first would
            // be the same bet taken twice.
            StabilityGate::fromConfig($this->config->get('sqlens.stability')),
        );
    }

    /**
     * The engine's provisioner, fully assembled. On PostgreSQL it is handed the
     * template BUILDER rather than a finished template: building one creates a
     * database, and that must not happen while a captor is merely being constructed —
     * the provisioner builds it inside `provision()`, after the guard has allowed the
     * run and the replica and pooler checks have passed.
     *
     * A driver with no provisioner returns null, which the captor reports as the named
     * unsupported-engine undetermined rather than falling back to pretend.
     */
    private function provisionerFor(string $key, string $connectionName): ?ShadowProvisioner
    {
        $prefix = $this->shadowPrefix();
        $connectionConfig = $this->connectionConfig($connectionName);

        return match ($key) {
            'pgsql' => new PgsqlShadowProvisioner(
                new ConnectionMaintenanceGateway($this->maintenanceConnection($connectionName, ConnectionMaintenanceGateway::MAINTENANCE_DATABASE)),
                $this->config,
                $this->database,
                fn (): string => ShadowDatabaseName::generate($prefix),
                $connectionConfig,
                new PgsqlVirginTemplateBuilder(
                    new ConnectionMaintenanceGateway($this->maintenanceConnection($connectionName, ConnectionMaintenanceGateway::MAINTENANCE_DATABASE)),
                    $this->config,
                    $this->database,
                    fn (): string => ShadowDatabaseName::generate(ShadowDatabaseName::templatePrefix($prefix)),
                    $connectionConfig,
                    $this->schemaDumpPath($connectionName),
                ),
                $connectionName,
            ),
            'mysql' => new MysqlShadowProvisioner(
                new ConnectionMysqlMaintenanceGateway($this->maintenanceConnection($connectionName, ConnectionMysqlMaintenanceGateway::MAINTENANCE_DATABASE)),
                new MysqlSchemaDumpReader(new StatementSplitter),
                $this->config,
                $this->database,
                fn (): string => ShadowDatabaseName::generate($prefix),
                $connectionConfig,
                $this->databaseName($connectionName),
                $this->schemaDumpPath($connectionName),
                $connectionName,
            ),
            default => null,
        };
    }

    /** The engine's replica probe — a read, so a replica is refused before any DDL. */
    private function replicaProbeFor(string $key): ?ReplicaProbe
    {
        return match ($key) {
            'pgsql' => new PgsqlReplicaProbe($this->database),
            'mysql' => new MysqlReplicaProbe($this->database),
            default => null,
        };
    }

    /**
     * A connection to an ADMIN database on the same server — never to the template or
     * the clone, so a maintenance link is never the thing being created or dropped.
     */
    private function maintenanceConnection(string $connectionName, string $database): Connection
    {
        $name = $connectionName.'__sqlens_maintenance_'.$database;

        $this->config->set('database.connections.'.$name, [
            ...$this->connectionConfig($connectionName),
            'database' => $database,
        ]);
        $this->database->purge($name);

        return $this->database->connection($name);
    }

    /**
     * The connection config the shadow databases are reached through: the direct
     * connection when one is configured (template operations break behind a
     * transaction pooler), else the run's own connection.
     *
     * @return array<string, mixed>
     */
    private function connectionConfig(string $connectionName): array
    {
        $direct = $this->config->get('sqlens.capture.shadow.direct_connection');
        $source = is_string($direct) && $direct !== '' ? $direct : $connectionName;
        $config = $this->config->get('database.connections.'.$source);
        $keyed = [];

        // Keyed explicitly rather than returned wholesale: a connection config is a
        // string-keyed map, and anything else in it is not a setting this can pass on.
        foreach (is_array($config) ? $config : [] as $key => $value) {
            if (is_string($key)) {
                $keyed[$key] = $value;
            }
        }

        return $keyed;
    }

    /**
     * The orphan sweep for a driver, or null when the engine has no shadow support to leak from.
     *
     * Built beside the provisioner and from the same maintenance gateway, because they are the two
     * halves of one promise: the provisioner creates a throwaway database and drops it, and this
     * removes what a previous run could not — a process killed mid-run never reaches its own
     * `finally`, and that is the only leak path a try/finally cannot cover.
     *
     * Assembling it opens no connection. `maintenanceConnection()` names one; the first query
     * happens when the captor sweeps, which is after the guard has allowed the run.
     */
    private function sweeperFor(string $key, string $connectionName): ShadowOrphanSweeper
    {
        // TWO engines, on one line, and both halves of it run — the shape is the point.
        //
        // This was a three-arm `match` with `default => null`, and that third arm was a line NO RUN
        // COULD ENTER: the only caller is `shadow()`, which returns `unknownDriver` unless
        // `formatterFor($key)` answered, and that answers for `pgsql` and `mysql` and nothing else.
        // An unreachable line is not a gap a test can close — it is a claim the code makes about a
        // state it has already excluded — and it cost the 100% floor on `develop` until it was
        // removed rather than tested around.
        //
        // Returning `null` there was also the wrong answer in the direction that matters: it means
        // "this run sweeps nothing", and a leak nobody sweeps is invisible.
        $catalog = $key === 'pgsql'
            ? new ConnectionMaintenanceGateway($this->maintenanceConnection($connectionName, ConnectionMaintenanceGateway::MAINTENANCE_DATABASE))
            : new ConnectionMysqlMaintenanceGateway($this->maintenanceConnection($connectionName, ConnectionMysqlMaintenanceGateway::MAINTENANCE_DATABASE));

        return new ShadowOrphanSweeper($catalog, $this->shadowPrefix(), $this->orphanThresholdSeconds());
    }

    /**
     * How old a shadow database has to be before the sweep will remove it.
     *
     * The floor is what makes a sweep safe under `--parallel`: a worker must never drop the
     * throwaway database another worker is migrating into right now. An hour is far beyond any real
     * run — the shadow timeout is measured in seconds — while still removing yesterday's leak on the
     * first run of the day.
     *
     * A configured value below the floor is RAISED to it rather than honored. Someone lowering it to
     * clean up faster would be trading a disk-space annoyance for the one mistake this whole class
     * is built to avoid, and the config comment says so.
     */
    private function orphanThresholdSeconds(): int
    {
        $configured = $this->config->get('sqlens.capture.shadow.orphan_after_seconds');

        return is_numeric($configured) ? max(self::ORPHAN_THRESHOLD_FLOOR, (int) $configured) : self::ORPHAN_THRESHOLD_FLOOR;
    }

    /**
     * Whether the configured direct connection reaches a DIFFERENT server than the run's own.
     *
     * `connectionConfig()` above resolves the direct connection and hands it to the provisioner
     * WITHOUT comparing it to anything, so a project that pointed it at the wrong entry would have
     * every `CREATE DATABASE` and every `DROP DATABASE` land on a server nobody named — and the run
     * would look ordinary while it happened. The setting exists to reach the same server around a
     * transaction pooler, which makes "same instance" its actual contract.
     *
     * Only the INSTANCE is compared. The direct connection legitimately names a different database:
     * provisioning connects to the maintenance database rather than the project's, so comparing the
     * full identity would refuse every correct configuration.
     *
     * No connection is opened. An unconfigured direct connection is not a difference — there is
     * nothing to disagree with.
     */
    private function directConnectionIsElsewhere(string $connectionName): bool
    {
        $direct = $this->config->get('sqlens.capture.shadow.direct_connection');

        if (! is_string($direct) || $direct === '') {
            return false;
        }

        return ! ShadowTargetIdentity::sameInstance(
            $this->rawConnectionConfig($direct),
            $this->rawConnectionConfig($connectionName),
        );
    }

    /**
     * One connection's configuration as a string-keyed map, or an empty one when it is not there.
     *
     * A connection name that resolves to nothing yields `[]`, and two empty maps compare EQUAL — so
     * a typo in `direct_connection` reads as "same instance" and passes this gate. That is
     * deliberate: a name that resolves to nothing fails at connect time with a message naming the
     * connection, which is a better diagnosis than a refusal about servers when no server was found.
     *
     * @return array<string, mixed>
     */
    private function rawConnectionConfig(string $name): array
    {
        $config = $this->config->get('database.connections.'.$name);
        $keyed = [];

        foreach (is_array($config) ? $config : [] as $key => $value) {
            if (is_string($key)) {
                $keyed[$key] = $value;
            }
        }

        return $keyed;
    }

    private function databaseName(string $connectionName): string
    {
        $database = $this->config->get('database.connections.'.$connectionName.'.database');

        return is_string($database) ? $database : '';
    }

    /**
     * Laravel's own dump location: `database/schema/<connection>-schema.sql`. The
     * shadow mode rebuilds from the project's committed schema, not from the live
     * database, on both engines — which is what keeps the template free of data.
     */
    private function schemaDumpPath(string $connectionName): string
    {
        return $this->app->databasePath('schema/'.$connectionName.'-schema.sql');
    }

    private function shadowPrefix(): string
    {
        $prefix = $this->config->get('sqlens.capture.shadow.database_prefix');

        return is_string($prefix) && $prefix !== '' ? $prefix : 'sqlens_shadow_';
    }

    private function shadowTimeout(): int
    {
        $timeout = $this->config->get('sqlens.capture.shadow.timeout');

        return is_int($timeout) && $timeout > 0 ? $timeout : 120;
    }

    /**
     * The migrations table, read in BOTH shapes the framework honors.
     *
     * `MigrationServiceProvider` does `is_array($migrations) ? ($migrations['table'] ?? null) :
     * $migrations`, so `'migrations' => 'custom_migrations'` — the shape Laravel used before 11 and
     * still accepts — names the table just as well as the array form does.
     *
     * Reading only `database.migrations.table` made that string invisible: the lookup returned null
     * and the fallback named `migrations`, a table the application does not use. An app upgraded
     * from Laravel 10 with a customized name therefore got a misdiagnosed "no migration table" skip,
     * and a shadow noise filter that filtered nothing.
     */
    private function migrationsTable(): string
    {
        $migrations = $this->config->get('database.migrations');
        $table = is_array($migrations) ? ($migrations['table'] ?? null) : $migrations;

        return is_string($table) && $table !== '' ? $table : 'migrations';
    }

    /**
     * The driver's canonicalization, from the registry that owns that mapping.
     *
     * It used to be a `match` here with the same two arms the registry's constructor registers, and
     * the docblock above called that deliberate. It was — but it also meant the registry had no
     * caller at all, so its `extend()` accepted third-party canonicalizations into a map nothing
     * ever read: a driver added "without touching a core file" would reach this method, miss the
     * `match`, and be reported as a driver with no capture wiring.
     *
     * The failure shapes are collapsed to null deliberately, because the caller already turns that
     * into `DriverResolutionFailure::unknownDriver($key)` and this change is about wiring rather
     * than about error reporting. The registry's richer reasons — no canonicalization registered
     * versus one that leaves a required capability empty — are worth surfacing, and that is its own
     * change rather than a side effect of this one.
     */
    private function canonicalizationFor(string $key): ?DriverCanonicalization
    {
        $canonicalization = $this->extensions->forDriver($key);

        return $canonicalization instanceof DriverCanonicalization ? $canonicalization : null;
    }

    private function formatterFor(string $key): ?BindingFormatter
    {
        return match ($key) {
            'pgsql' => new PgsqlBindingFormatter,
            'mysql' => new MysqlBindingFormatter,
            default => null,
        };
    }

    /**
     * The context every canonical statement carries — the driver whose grammar it
     * describes, the run profile, and the strict-tools flag. The parsed server
     * version is not attached yet; it arrives with the version-pin unit, so a rule
     * that needs a version still yields a named undetermined until then.
     *
     * Public because it is the ONE source of a run's subject context: the captor is
     * canonicalized under it, and the finding collector must build its subjects under
     * the SAME context — a second, separately-built context would let the two drift.
     */
    public function subjectContextFor(string $key): SubjectContext
    {
        $profile = $this->config->get('sqlens.profile');
        $strictTools = $this->config->get('sqlens.strict_tools') === true;

        return new SubjectContext(
            driver: $key,
            profile: is_string($profile) ? $profile : 'local',
            strictTools: $strictTools,
            // The path binding, built from the SAME resolver the lint layer uses. It rides on the
            // context rather than reaching a rule some other way, because this method is documented
            // as the ONE source of a run's subject context — and a second, separately-built binding
            // would be exactly the drift that documentation exists to prevent.
            pathBinding: new PathBinding(
                new MigrationPaths($this->app, $this->app->make(Migrator::class), $this->config)->all(),
                $this->app->basePath(),
                $this->config->get('sqlens.security.include_vendor_migrations') === true,
            ),
        );
    }

    /**
     * A config value read as a list of strings, dropping anything that is not one —
     * the pre-scan surfaces and the indirect-call allowlist are both string lists.
     *
     * @return list<string>
     */
    private function stringList(string $key): array
    {
        $value = $this->config->get($key);

        if (! is_array($value)) {
            return [];
        }

        $strings = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $strings[] = $item;
            }
        }

        return $strings;
    }
}
