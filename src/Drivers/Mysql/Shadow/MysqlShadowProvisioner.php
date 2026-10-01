<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\DatabaseManager;
use PDOException;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Capture\Shadow\ShadowConnectionLatch;
use Pushery\SQLens\Capture\Shadow\ShadowSession;
use Pushery\SQLens\Contracts\ShadowProvisioner;
use Pushery\SQLens\Drivers\EffectiveConnectionConfig;
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
 *   2. The user must be able to create AND drop the database this run will create,
 *      or the run is undetermined before anything is created. The name is generated
 *      first for that reason: MySQL grants both per database, so the question only
 *      has an answer about a name.
 *   3. The dump is read BEFORE any database is created, so a missing or unparseable
 *      dump fails with nothing to clean up.
 *   4. The generated name must be free — a collision never touches a database the
 *      mode did not create.
 *
 * Only then is the database created and the dump replayed statement by statement.
 * A server that refuses the `CREATE DATABASE` all the same makes the run the named
 * undetermined of step 2, since nothing was created. If any statement of the replay
 * fails, the half-built database is dropped and the run is undetermined — a
 * partially rebuilt schema is green with nothing behind it.
 */
final readonly class MysqlShadowProvisioner implements ShadowProvisioner
{
    /** MySQL's ER_DBACCESS_DENIED_ERROR, the answer to a `CREATE DATABASE` the account may not issue. */
    private const int DATABASE_ACCESS_DENIED = 1044;

    /**
     * @param  MysqlMaintenanceGateway  $source  the same reads on the connection being examined,
     *                                           asked only for the source's character set. That
     *                                           account always sees its own database; the one
     *                                           allowed to create and drop the shadow databases
     *                                           may hold no privilege on it, and MySQL lists a
     *                                           database in `information_schema.SCHEMATA` only to
     *                                           an account that does
     * @param  Closure(): string  $nameFactory  produces a fresh shadow database name (within MySQL's 64-char limit)
     * @param  array<string, mixed>  $shadowConnectionConfig  the connection config the clone is registered under, its `database` replaced by the shadow name
     */
    public function __construct(
        private MysqlMaintenanceGateway $gateway,
        private MysqlMaintenanceGateway $source,
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

        // Named before the privilege question, because MySQL answers it per database: the
        // documented grant reaches the shadow prefix and nothing else. Naming creates nothing.
        $name = ($this->nameFactory)();

        if (! $this->gateway->canCreateAndDropDatabase($name)) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowInsufficientPrivileges);
        }

        // Read the dump BEFORE creating anything: a missing or unparseable dump then
        // fails with no database to clean up.
        $plan = $this->dumpReader->read($this->schemaDumpPath);

        if ($plan instanceof DumpFailure) {
            // The diagnosis rides along for a person reading the log: which statement, on which
            // line. It names a refused statement by its keywords, never by its text.
            throw new ShadowProvisioningUndetermined($plan->reason, $plan->diagnosis());
        }

        if ($this->gateway->databaseExists($name)) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowNameCollision);
        }

        // Asked on the source's own connection. Asked on the maintenance one, whose account needs
        // no privilege on the application's database, SCHEMATA has no row for it, the gateway
        // answers its built-in default, and every table that inherits the database's collation
        // then reads as drift.
        $characterSet = $this->source->characterSetOf($this->sourceDatabase);
        $this->createDatabase($name, $characterSet);
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
     * Create the throwaway database, and turn the server's refusal into the result the
     * grants predicted.
     *
     * The grants read in step 2 predict the answer; the server's refusal is the answer,
     * and a refused `CREATE DATABASE` created nothing. So a refusal becomes the same
     * named undetermined, not an exception carrying the connection's details. Every
     * other failure is a real one and propagates.
     *
     * @param  array{charset: string, collation: string}  $characterSet
     */
    private function createDatabase(string $name, array $characterSet): void
    {
        try {
            $this->gateway->createDatabase($name, $characterSet['charset'], $characterSet['collation']);
        } catch (PDOException $failure) {
            if (($failure->errorInfo[1] ?? null) !== self::DATABASE_ACCESS_DENIED) {
                throw $failure;
            }

            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowInsufficientPrivileges);
        }
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
            // The dump drops and recreates every table it names, so it runs nowhere but the database
            // just created for it.
            ShadowConnectionLatch::assertReaches($this->db->connection($name), $name);

            // The dump's own header asks for this, and the reader drops that header. `mysqldump`
            // writes `/*!40014 SET … FOREIGN_KEY_CHECKS=0 */` and `… UNIQUE_CHECKS=0` before the
            // tables, and `MysqlSchemaDumpReader` skips every whole-statement `/*!… SET …*/` as
            // session state — while the MySQL manual's Comments section is explicit that a versioned
            // comment is executed by the server.
            //
            // It matters on almost every real schema, because `mysqldump` emits tables
            // alphabetically. Verified on MySQL 8.4.10 with Laravel's own dump options
            // (`--skip-comments --skip-set-charset --tz-utc --no-data`): for `orders` → `users` the child
            // is written first, and replaying the header-stripped dump fails with
            // `ERROR 1824 (HY000) Failed to open the referenced table 'users'`. With this line the same
            // dump replays clean. Without it, shadow mode would be permanently `undetermined` wherever
            // a child table sorts before its parent — `orders`/`users`, `comments`/`posts`,
            // `accounts`/`users`.
            //
            // Set here rather than by honoring the dump's directives, and that is the narrower fix: it
            // does not depend on which `/*!…*/` lines a given mysqldump version happens to write.
            $pdo->exec('SET SESSION foreign_key_checks = 0, unique_checks = 0');

            foreach ($plan->statements as $statement) {
                $pdo->exec($statement);
            }

            // The reader refuses every statement that could move this session to another database,
            // so this holds by construction. It is asked anyway, of the session the dump ran on,
            // because the replay is the one place where the answer being wrong writes into a
            // database that is not a throwaway one, and a run over it must not come back green.
            // A query that cannot even answer reads as no database, so the check fails closed.
            $asked = $pdo->query('select database()');
            $ended = $asked === false ? false : $asked->fetchColumn();

            if ($ended !== $name) {
                throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowMysqlReplayFailed, sprintf(
                    'The replay session ended in %s instead of the throwaway database "%s".',
                    is_string($ended) ? '"'.$ended.'"' : 'no database',
                    $name,
                ));
            }

            // The switches above are for the replay and must not reach the migrations. The runner takes
            // this same connection from the manager, and with the checks still off MySQL would drop a
            // table another one references, or add a foreign key to one that does not exist, both of
            // which the deploy refuses. Purged, the runner opens a fresh session with the server's own
            // checks, as `migrate` does when it deploys.
            $this->db->purge($name);
        } catch (Throwable $failure) {
            $this->db->purge($name);
            $this->gateway->dropDatabase($name);

            // A refusal before the first statement keeps its own reason and detail: the replay did not
            // fail, it was never started.
            if ($failure instanceof ShadowProvisioningUndetermined) {
                throw $failure;
            }

            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowMysqlReplayFailed);
        }
    }

    /**
     * Register a runtime connection pointing at the throwaway database, under the
     * shadow name, so the replay and the later runner resolve it. The URL is resolved
     * before the database is swapped, so the swap is the database the connection reaches.
     */
    private function registerConnection(string $name): void
    {
        $this->config->set('database.connections.'.$name, EffectiveConnectionConfig::onDatabase($this->shadowConnectionConfig, $name));

        $this->db->purge($name);
    }
}
