<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Shadow;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Capture\Shadow\VirginTemplate;
use Pushery\SQLens\Exceptions\NotAVirginTemplate;
use Pushery\SQLens\Exceptions\ShadowProvisioningUndetermined;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * Builds the empty database a PostgreSQL shadow clone is made from.
 *
 * The shadow mode needs a template that has the project's SCHEMA and none of its
 * DATA, because `CREATE DATABASE … TEMPLATE` copies whatever it is pointed at. The
 * obvious shortcut — point it at the live database — is exactly the harm the mode
 * exists to avoid, so the template is built here instead:
 *
 *   1. A fresh database from `template0` (PostgreSQL's pristine template, never
 *      `template1`, which a site may have added objects to).
 *   2. The project's `schema:dump` replayed into it — structure, no rows.
 *   3. Every user table PROBED for a row. Not `pg_stat_user_tables`, whose counts
 *      are planner estimates that can read zero for a populated table; an exact
 *      `select 1 … limit 1` per table, which cannot be wrong in the dangerous
 *      direction. The probes are batched into a bounded number of statements —
 *      exactness is the point, a round trip per table is not.
 *   4. Only then is a {@see VirginTemplate} minted — and this is the one place in
 *      the shipped code allowed to mint one.
 *
 * The template is a throwaway carrying the shadow prefix and is dropped alongside
 * the clone. Anything that goes wrong while building it is a named undetermined,
 * never a fall back to some other database: a shadow run that cannot get a safe
 * template does not run.
 */
final readonly class PgsqlVirginTemplateBuilder
{
    /**
     * How many emptiness probes travel in one statement.
     *
     * A compromise with one bad end on each side: one statement for every table is a
     * round trip per table, and one statement for ALL of them grows without bound
     * with the schema. Sixty-four keeps the statement small enough to be ordinary
     * and turns the common few-hundred-table project into a handful of round trips.
     */
    private const int PROBE_CHUNK = 64;

    /**
     * @param  Closure(): string  $nameFactory  produces a fresh template database name
     * @param  array<string, mixed>  $connectionConfig  the config a connection INTO the template is registered with, its `database` replaced by the template name
     */
    public function __construct(
        private MaintenanceGateway $gateway,
        private Repository $config,
        private DatabaseManager $db,
        private Closure $nameFactory,
        private array $connectionConfig,
        private string $schemaDumpPath,
    ) {}

    /**
     * Build the template and vouch for it.
     *
     * @throws ShadowProvisioningUndetermined when the dump is unreadable or unusable, or the name is taken
     */
    public function build(): VirginTemplate
    {
        $sql = $this->readDump();
        $name = ($this->nameFactory)();

        // Never adopt a database we did not create — the same rule the clone follows.
        if ($this->gateway->databaseExists($name)) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowNameCollision);
        }

        $this->gateway->createEmptyDatabase($name);

        try {
            $connection = $this->connectionInto($name);

            // Replayed on the PDO handle, the same way the MySQL provisioner replays
            // its dump — one established path, not a second one. The statement text is
            // the project's own schema dump, and a bad statement becomes a throwable
            // this method catches and drops the half-built database for.
            $connection->getPdo()->exec($sql);

            // The count is the whole guarantee, so it happens on the database that was
            // actually built, immediately before vouching for it.
            $template = VirginTemplate::verifiedEmpty($name, $this->rowsIn($connection));

            // Let go of the template before handing it on. PostgreSQL refuses a
            // database with any other active connection as a `TEMPLATE` source, so a
            // builder that kept its own connection open would make every template it
            // produced unusable — found by cloning one for real.
            $this->db->purge($name);

            return $template;
        } catch (Throwable $failure) {
            // A half-built template is never left behind, and never handed on: the
            // database is dropped and the failure surfaces. Better no shadow run than
            // a clone of something nobody verified.
            $this->discard($name);

            // A template that turned out to hold ROWS propagates as itself. Folding it
            // into a generic "the build failed" would lose exactly the fact that
            // matters — that a database with data was offered as a clone source — and
            // this refusal is the loudest thing the shadow mode can say.
            if ($failure instanceof NotAVirginTemplate || $failure instanceof ShadowProvisioningUndetermined) {
                throw $failure;
            }

            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowTemplateBuildFailed);
        }
    }

    /** Release and drop a template — called with the clone's teardown. */
    public function discard(string $database): void
    {
        $this->db->purge($database);
        $this->gateway->dropDatabase($database);
    }

    /**
     * How many rows the database holds, across every user table.
     *
     * Exact, not estimated: each table is probed with `select 1 … limit 1`, so a
     * table with rows contributes 1 and the total is non-zero. The estimate columns
     * PostgreSQL offers (`pg_stat_user_tables.n_live_tup`) can read zero for a
     * populated table that has not been analyzed — which would be a false "virgin"
     * in exactly the case that matters.
     *
     * The probes travel TOGETHER. One `selectOne` per table is a round trip per
     * table, and the normal case is the one that pays it in full: a template is
     * expected to be empty, so every probe runs and none of them exits early. On a
     * project with a few hundred tables that is a few hundred round trips to learn
     * a fact about an empty database — and against a managed server, where a round
     * trip is milliseconds rather than microseconds, it is the whole cost of
     * building a template.
     *
     * Chunked rather than one statement, so the statement stays a size a server will
     * parse whatever the schema looks like: the query count is `ceil(tables / 64)`,
     * which is bounded and, unlike the old loop, guarded — see the shadow suite.
     *
     * The probe statement returns one ROW per non-empty table rather than a count the
     * server computed, so the answer needs no interpretation on this side.
     *
     * Each arm is parenthesized because it carries its own LIMIT. Without the
     * parentheses PostgreSQL reads the LIMIT as belonging to the whole UNION, which
     * would cap the result at one row and report at most one populated table.
     */
    #[RawSql(reason: 'counts rows in a table the builder is about to declare untouched; the claim is only worth making if it was measured')]
    private function rowsIn(Connection $connection): int
    {
        $found = 0;

        foreach (array_chunk($this->userTables($connection), self::PROBE_CHUNK) as $chunk) {
            $probes = array_map(
                fn (array $member): string => sprintf(
                    '(select 1 from %s.%s limit 1)',
                    $this->quoteIdentifier($member[0]),
                    $this->quoteIdentifier($member[1]),
                ),
                $chunk,
            );

            // The ROWS are counted, not a scalar the server computed. `select count(*)` would
            // hand back a value this code has to interpret — and interpreting it wrong in the
            // lenient direction produces the one answer this method exists to make impossible,
            // a template vouched for as empty because nobody could read the count. Counting the
            // returned rows removes the interpretation: each non-empty table contributes exactly
            // one row, so there is no value to misread and no defensive branch to leave unproven.
            $found += count($connection->select(implode(' union all ', $probes)));
        }

        return $found;
    }

    /**
     * The ordinary tables of the database, excluding PostgreSQL's own catalogs.
     *
     * @return list<array{0: string, 1: string}>
     */
    #[RawSql(reason: 'enumerates user tables from the catalog, because the template check has to cover what is there rather than what somebody listed')]
    private function userTables(Connection $connection): array
    {
        $tables = [];

        $rows = $connection->select(
            "select table_schema, table_name from information_schema.tables
             where table_type = 'BASE TABLE'
               and table_schema not in ('pg_catalog', 'information_schema')"
        );

        foreach ($rows as $row) {
            $schema = is_object($row) ? $row->table_schema ?? null : null;
            $table = is_object($row) ? $row->table_name ?? null : null;

            if (is_string($schema) && is_string($table)) {
                $tables[] = [$schema, $table];
            }
        }

        return $tables;
    }

    /** The project's schema definition, or a named undetermined when it cannot be read. */
    private function readDump(): string
    {
        if (! is_file($this->schemaDumpPath) || ! is_readable($this->schemaDumpPath)) {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowPgsqlSchemaDumpMissing);
        }

        $contents = @file_get_contents($this->schemaDumpPath);

        if ($contents === false || trim($contents) === '') {
            throw new ShadowProvisioningUndetermined(UndeterminedReason::ShadowPgsqlSchemaDumpMissing);
        }

        return $contents;
    }

    /** A runtime connection INTO the template, so the dump can be replayed and the rows counted. */
    private function connectionInto(string $name): Connection
    {
        $this->config->set('database.connections.'.$name, [
            ...$this->connectionConfig,
            'database' => $name,
        ]);

        $this->db->purge($name);

        return $this->db->connection($name);
    }

    /** Double-quote an identifier, doubling any embedded double quote. */
    private function quoteIdentifier(string $identifier): string
    {
        return '"'.str_replace('"', '""', $identifier).'"';
    }
}
