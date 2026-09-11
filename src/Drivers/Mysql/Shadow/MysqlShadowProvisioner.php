<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\DatabaseManager;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Capture\Shadow\ShadowSession;
use Pushery\SQLens\Contracts\ShadowProvisioner;
use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * The MySQL side of the truth mode. MySQL has no `CREATE DATABASE … TEMPLATE`, so
 * the throwaway database is built by creating it with the source's character set
 * and collation, then REPLAYING the `schema:dump` artifact into it — or the run
 * says honestly that it could not, rather than linting against an empty or
 * half-built database.
 *
 * Like the PostgreSQL provisioner it is a pure ORCHESTRATOR over a narrow
 * {@see MysqlMaintenanceGateway} port and the {@see MysqlSchemaDumpReader} (the one
 * dump splitter, never a second). The order encodes the safety story:
 *
 *   1. MariaDB is a declared non-goal — refused as a named unsupported result, not
 *      routed through the MySQL path.
 *   2. The user must be able to create AND drop databases, or the run is
 *      undetermined before anything is created.
 *   3. The dump is read BEFORE any database is created, so a missing or unparseable
 *      dump fails with nothing to clean up.
 *   4. The generated name must be free — a collision never touches a database the
 *      mode did not create.
 *
 * Only then is the database created and the dump replayed statement by statement.
 * If any statement fails, the half-built database is dropped and the run is
 * undetermined — a partially rebuilt schema is green with nothing behind it.
 */
final readonly class MysqlShadowProvisioner implements ShadowProvisioner
{
    /**
     * @param  Closure(): string  $nameFactory  produces a fresh shadow database name (within MySQL's 64-char limit)
     * @param  array<string, mixed>  $shadowConnectionConfig  the connection config the clone is registered under, its `database` replaced by the shadow name
     */
    public function __construct(
        private MysqlMaintenanceGateway $gateway,
        private MysqlSchemaDumpReader $dumpReader,
        private Repository $config,
        private DatabaseManager $db,
        private Closure $nameFactory,
        private array $shadowConnectionConfig,
        private string $sourceDatabase,
        private string $schemaDumpPath,
        private string $sourceConnection,
    ) {}

    public function supports(string $driver): bool
    {
        return $driver === 'mysql';
    }

    public function provision(): ShadowSession
    {
        if ($this->gateway->isMariaDb()) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::UnsupportedEngine);
        }

        if (! $this->gateway->canCreateAndDropDatabases()) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowInsufficientPrivileges);
        }

        // Read the dump BEFORE creating anything: a missing or unparseable dump then
        // fails with no database to clean up.
        $plan = $this->dumpReader->read($this->schemaDumpPath);

        if ($plan instanceof DumpFailure) {
            throw new ShadowProvisioningUndetermined($plan->reason);
        }

        $name = ($this->nameFactory)();

        if ($this->gateway->databaseExists($name)) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowNameCollision);
        }

        $characterSet = $this->gateway->characterSetOf($this->sourceDatabase);
        $this->gateway->createDatabase($name, $characterSet['charset'], $characterSet['collation']);
        $this->registerConnection($name);

        $this->replay($name, $plan);

        return new ShadowSession(
            $name,
            $name,
            $this->sourceConnection,
            new DateTimeImmutable('now', new DateTimeZone('UTC')),
        );
    }

    public function destroy(ShadowSession $session): void
    {
        $this->db->purge($session->connectionName);

        $this->gateway->dropDatabase($session->shadowDatabase);
    }

    /**
     * Replay the dump's executable statements into the freshly created database. A
     * statement that fails drops the half-built database and makes the run
     * undetermined — never a lint against a schema that only partially rebuilt.
     */
    #[RawSql(reason: 'replays the project\'s own `schema:dump` output, which is a file of DDL statements and not something any builder has a verb for; it runs on the PDO handle so no mysql client binary is needed, and PDO\'s exception error mode turns a bad statement into the throwable this method catches')]
    private function replay(string $name, SchemaDumpPlan $plan): void
    {
        // Replay the dump's statements directly on the PDO handle: they are trusted
        // schema:dump SQL, not literal strings, and PDO's exception error mode turns
        // a bad statement into a throwable this method catches. No mysql client binary
        // is required.
        $pdo = $this->db->connection($name)->getPdo();

        try {
            foreach ($plan->statements as $statement) {
                $pdo->exec($statement);
            }
        } catch (Throwable) {
            $this->db->purge($name);
            $this->gateway->dropDatabase($name);

            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowMysqlReplayFailed);
        }
    }

    /**
     * Register a runtime connection pointing at the throwaway database, under the
     * shadow name, so the replay and the later runner resolve it.
     */
    private function registerConnection(string $name): void
    {
        $this->config->set('database.connections.'.$name, [
            ...$this->shadowConnectionConfig,
            'database' => $name,
        ]);

        $this->db->purge($name);
    }
}
