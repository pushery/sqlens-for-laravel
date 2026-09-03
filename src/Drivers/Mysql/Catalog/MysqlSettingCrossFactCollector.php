<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SettingCrossFacts;
use Pushery\SQLens\Contracts\SettingCrossFactCollector;
use Pushery\SQLens\Findings\UndeterminedReason;
use Throwable;

/**
 * The MySQL facts that make a server-baseline finding concrete.
 *
 * Scoped to the audited schema on purpose. `information_schema.columns` spans every database on the
 * instance, and the `mysql` system schema alone carries a handful of columns with an implicit
 * `ON UPDATE CURRENT_TIMESTAMP` — reporting those to a project would be reporting MySQL's own
 * bookkeeping back to them as their problem.
 */
final readonly class MysqlSettingCrossFactCollector implements SettingCrossFactCollector
{
    /** The fact name a rule declares to receive the affected-column list. */
    public const string TIMESTAMP_AUTO_UPDATE_COLUMNS = 'timestamp_auto_update_columns';

    /** The fact name a rule declares to receive the tables still on a pre-DYNAMIC row format. */
    public const string LEGACY_ROW_FORMAT_TABLES = 'legacy_row_format_tables';

    /** The fact name a rule declares to receive which storage engines the server refuses outright. */
    public const string DISABLED_STORAGE_ENGINES = 'disabled_storage_engines';

    /** The fact name a rule declares to learn whether the timezone tables hold anything. */
    public const string TIME_ZONE_TABLES_LOADED = 'time_zone_tables_loaded';

    /**
     * Where the general query log is being written — `FILE`, `TABLE`, both, or `NONE`.
     *
     * Read beside `general_log`, because the switch alone does not say how far the statements
     * travel. A log going to `mysql.general_log` is readable by whoever holds SELECT on that table;
     * a log going to a FILE usually sits outside whatever protects the database, is often
     * world-readable, and is routinely swept into log shipping. Same setting, two different
     * exposures, and the destination is the half that decides which.
     *
     * A separate variable rather than something derivable: `general_log` is a boolean and says
     * nothing about output. Without this fact the rule can only report that recording is happening,
     * which is what its limitations said out loud before this existed.
     */
    public const string GENERAL_LOG_OUTPUT = SettingCrossFactCollector::GENERAL_LOG_OUTPUT;

    /** The fact name a rule declares to receive table names that are not all lower case. */
    public const string MIXED_CASE_TABLES = 'mixed_case_tables';

    /**
     * The fact name a rule declares to learn which accounts hold the `FILE` privilege.
     *
     * Aliased from the core vocabulary rather than declared here like its five neighbors: the rule
     * that reads it lives in the CORE namespace, which may not name a driver, so the name itself
     * had to move somewhere both sides may see. Kept as a constant here anyway so the query below
     * and the five above still read alike.
     */
    public const string FILE_PRIVILEGE_ACCOUNTS = SettingCrossFacts::FILE_PRIVILEGE_ACCOUNTS;

    public function __construct(private ReaderSession $session, private string $schema) {}

    public function collect(): SettingCrossFacts
    {
        return $this->withFilePrivilegeAccounts($this->withMixedCaseTables($this->withTimeZoneTables(
            $this->withGeneralLogOutput($this->withDisabledEngines($this->withLegacyRowFormats($this->withTimestampColumns(SettingCrossFacts::none())))),
        )));
    }

    /**
     * Where the general query log goes, read beside `general_log`.
     *
     * `@@global.log_output` is a SET, so the honest answer is the server's own string — `FILE`,
     * `TABLE`, `FILE,TABLE` or `NONE`. It is passed through rather than mapped into a shape of our
     * own: the rule quotes it, and inventing a vocabulary here would mean the finding says something
     * MySQL never said.
     *
     * A refusal is `unavailable` with its reason, never a guessed destination. "The log is on and we
     * could not tell where it goes" and "the log is on and goes to a table" are different sentences,
     * and only one of them is safe to write when the read failed.
     */
    #[RawSql(reason: 'reads a server variable beside the one under judgment; a session variable is not a model and no builder expression names it')]
    private function withGeneralLogOutput(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                'select @@global.log_output as o',
            ));
        } catch (Throwable $exception) {
            return $facts->withUnavailable(
                'general_log',
                self::GENERAL_LOG_OUTPUT,
                UndeterminedReason::MissingPrivilege,
                $exception->getMessage(),
            );
        }

        $output = null;

        foreach ($rows as $row) {
            $candidate = is_object($row) ? ($row->o ?? null) : null;
            $output = is_string($candidate) && trim($candidate) !== '' ? trim($candidate) : null;
        }

        return $output === null
            ? $facts->withUnavailable(
                'general_log',
                self::GENERAL_LOG_OUTPUT,
                UndeterminedReason::CatalogReadFailed,
                'the server did not answer where the general log is written',
            )
            : $facts->withMeasured('general_log', self::GENERAL_LOG_OUTPUT, $output);
    }

    /**
     * Which accounts hold `FILE`, read beside `local_infile`.
     *
     * The two together are a different sentence from either alone. `local_infile` on says the server
     * would ASK a client for a file; an account with `FILE` says somebody on this instance can also
     * read and write files on the SERVER's disk. One is a capability nobody may be using, the pair
     * is a path from a hijacked connection to the host's filesystem.
     *
     * Read from the grant table rather than from `information_schema.USER_PRIVILEGES`, and that is
     * the whole reason this is a real read rather than a convenience: the information_schema view
     * NARROWS SILENTLY to what the caller may see. Reading it would answer "no account holds FILE"
     * on exactly the restricted connection where the question matters, with nothing raised. The
     * grant table refuses instead — and a refusal is a fact the consumer can act on.
     */
    #[RawSql(reason: 'cross-checks a server setting against the accounts that could exploit it; the grant catalog is not a model')]
    private function withFilePrivilegeAccounts(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                "select User as u, Host as h from mysql.user where File_priv = 'Y' order by User, Host limit 25",
            ));
        } catch (Throwable $exception) {
            // The arm this fact exists for. On a managed MySQL a refused grant read is the ordinary
            // case, and the rule that consumes this must report that it could not check rather than
            // quietly declining to escalate — those two are the same silence otherwise.
            return $facts->withUnavailable(
                'local_infile',
                self::FILE_PRIVILEGE_ACCOUNTS,
                UndeterminedReason::MissingPrivilege,
                $exception->getMessage(),
            );
        }

        $accounts = [];

        foreach ($rows as $row) {
            $user = is_object($row) ? ($row->u ?? null) : null;
            $host = is_object($row) ? ($row->h ?? null) : null;

            if (is_scalar($user) && is_scalar($host)) {
                $accounts[] = "'".$user."'@'".$host."'";
            }
        }

        // The empty list is a real answer here — measured, a stock 8.4 grants FILE to `root` and to
        // nobody else, so a server where the audit sees none is a server that narrowed the account
        // list or genuinely has none. Which of the two it is has already been decided above: a read
        // that failed never reaches this line.
        return $facts->withMeasured('local_infile', self::FILE_PRIVILEGE_ACCOUNTS, implode(', ', $accounts));
    }

    /**
     * Table names in this schema that are not all lower case.
     *
     * Compared in SQL with a BINARY collation on purpose. The obvious `WHERE TABLE_NAME !=
     * LOWER(TABLE_NAME)` finds nothing on a server whose information_schema collation is
     * case-insensitive — the comparison the query relies on is the very thing the server is
     * configured not to make. Casting to binary asks the question the rule actually has.
     */
    #[RawSql(reason: 'counts tables whose names would change meaning under a different lower_case_table_names; a catalog question with no builder form')]
    private function withMixedCaseTables(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                'select TABLE_NAME as t from information_schema.tables '
                .'where TABLE_SCHEMA = ? and cast(TABLE_NAME as binary) != cast(lower(TABLE_NAME) as binary) '
                .'order by TABLE_NAME limit 25',
                [$this->schema],
            ));
        } catch (Throwable $exception) {
            return $facts->withUnavailable(
                'lower_case_table_names',
                self::MIXED_CASE_TABLES,
                UndeterminedReason::CatalogReadFailed,
                $exception->getMessage(),
            );
        }

        $tables = [];

        foreach ($rows as $row) {
            $name = is_object($row) ? ($row->t ?? null) : null;

            if (is_scalar($name)) {
                $tables[] = (string) $name;
            }
        }

        return $facts->withMeasured('lower_case_table_names', self::MIXED_CASE_TABLES, implode(', ', $tables));
    }

    /**
     * Whether `mysql.time_zone_name` holds anything.
     *
     * Counted rather than listed: the answer a rule needs is "can this server resolve a named zone
     * at all", and 600-odd zone names in a finding would drown the sentence that matters. A count of
     * zero is a real answer — the tables exist and are empty, which is what a fresh install ships.
     *
     * Reading `mysql.time_zone_name` widens the reader's relation allowlist on purpose. That red is
     * the review moment the guard exists to force: a settings reader reaching into the `mysql`
     * schema is worth one deliberate look.
     */
    #[RawSql(reason: 'asks whether the time-zone tables are populated at all; mysql.time_zone is a system table, not a model')]
    private function withTimeZoneTables(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                'select count(*) as c from mysql.time_zone_name',
            ));
        } catch (Throwable $exception) {
            // The ordinary case on a managed database, and emphatically not "the tables are loaded".
            return $facts->withUnavailable(
                'time_zone',
                self::TIME_ZONE_TABLES_LOADED,
                UndeterminedReason::MissingPrivilege,
                $exception->getMessage(),
            );
        }

        $count = null;

        foreach ($rows as $row) {
            $candidate = is_object($row) ? ($row->c ?? null) : null;
            $count = is_numeric($candidate) ? (int) $candidate : null;
        }

        return $count === null
            ? $facts->withUnavailable(
                'time_zone',
                self::TIME_ZONE_TABLES_LOADED,
                UndeterminedReason::CatalogReadFailed,
                'the server did not answer the timezone-table count',
            )
            // The VALUE is the count as a string, so a rule can name it; the STATE stays `measured`
            // even at zero, because zero is what the question was asking.
            : $facts->withMeasured('time_zone', self::TIME_ZONE_TABLES_LOADED, (string) $count);
    }

    /**
     * Which storage engines this server refuses outright.
     *
     * Read beside `default_storage_engine` because the two together answer a question neither can
     * alone: a default of MyISAM is a hazard, and a default of MyISAM on a server that refuses
     * MyISAM is a setting that cannot bite. The empty string is the ordinary answer and means
     * "nothing is disabled" — measured, MySQL returns '' rather than NULL for it.
     */
    #[RawSql(reason: 'reads which storage engines exist and in what state, so a setting is judged against what the server can actually do')]
    private function withDisabledEngines(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                'select VARIABLE_VALUE as v from performance_schema.global_variables where VARIABLE_NAME = ?',
                ['disabled_storage_engines'],
            ));
        } catch (Throwable $exception) {
            return $facts->withUnavailable(
                'default_storage_engine',
                self::DISABLED_STORAGE_ENGINES,
                UndeterminedReason::CatalogReadFailed,
                $exception->getMessage(),
            );
        }

        $value = null;

        foreach ($rows as $row) {
            $candidate = is_object($row) ? ($row->v ?? null) : null;
            $value = is_scalar($candidate) ? (string) $candidate : null;
        }

        // A variable the server did not name at all is NOT an empty answer — it is an unread one.
        // Collapsing the two would let a rule state "nothing is disabled" about a server it could
        // not ask.
        return $rows === []
            ? $facts->withUnavailable(
                'default_storage_engine',
                self::DISABLED_STORAGE_ENGINES,
                UndeterminedReason::CatalogReadFailed,
                'the server did not report disabled_storage_engines',
            )
            : $facts->withMeasured('default_storage_engine', self::DISABLED_STORAGE_ENGINES, $value);
    }

    /**
     * Tables still carrying a pre-DYNAMIC row format.
     *
     * Read for the row-format rule, and NOT as a substitute for its judgment: a server handing out
     * the right default while old tables carry `Compact` is a different problem with a different
     * fix, and conflating the two would send a reader to a config file that is already correct.
     */
    #[RawSql(reason: 'reads per-table row formats out of information_schema to see whether a setting still has anything to bite on')]
    private function withLegacyRowFormats(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                'select TABLE_NAME as t, ROW_FORMAT as f from information_schema.tables '
                .'where TABLE_SCHEMA = ? and ENGINE = ? and ROW_FORMAT in (?, ?) '
                .'order by TABLE_NAME limit 25',
                [$this->schema, 'InnoDB', 'Compact', 'Redundant'],
            ));
        } catch (Throwable $exception) {
            return $facts->withUnavailable(
                'innodb_default_row_format',
                self::LEGACY_ROW_FORMAT_TABLES,
                UndeterminedReason::CatalogReadFailed,
                $exception->getMessage(),
            );
        }

        $tables = [];

        foreach ($rows as $row) {
            $table = is_object($row) ? ($row->t ?? null) : null;
            $format = is_object($row) ? ($row->f ?? null) : null;

            if (is_scalar($table) && is_scalar($format)) {
                $tables[] = $table.' ('.$format.')';
            }
        }

        return $facts->withMeasured('innodb_default_row_format', self::LEGACY_ROW_FORMAT_TABLES, implode(', ', $tables));
    }

    #[RawSql(reason: 'reads column defaults out of information_schema; the explicit_defaults_for_timestamp question only means something against real columns')]
    private function withTimestampColumns(SettingCrossFacts $facts): SettingCrossFacts
    {
        try {
            $rows = $this->session->read(fn (Connection $db): array => $db->select(
                'select TABLE_NAME as t, COLUMN_NAME as c from information_schema.columns '
                .'where TABLE_SCHEMA = ? and EXTRA like ? order by TABLE_NAME, COLUMN_NAME limit 25',
                [$this->schema, '%on update CURRENT_TIMESTAMP%'],
            ));
        } catch (Throwable $exception) {
            // The distinction the whole collaborator exists for: this is NOT an empty result. A rule
            // told "none" here would state that nothing is affected about a catalog nobody read.
            return $facts->withUnavailable(
                'explicit_defaults_for_timestamp',
                self::TIMESTAMP_AUTO_UPDATE_COLUMNS,
                UndeterminedReason::CatalogReadFailed,
                $exception->getMessage(),
            );
        }

        $columns = [];

        foreach ($rows as $row) {
            $table = is_object($row) ? ($row->t ?? null) : null;
            $column = is_object($row) ? ($row->c ?? null) : null;

            if (is_scalar($table) && is_scalar($column)) {
                $columns[] = $table.'.'.$column;
            }
        }

        // Capped at 25 by the query rather than trimmed here, so the round trip stays bounded on a
        // schema with thousands of columns. A finding listing 25 examples makes the point; one
        // listing 4000 is a wall of text nobody reads.
        return $facts->withMeasured(
            'explicit_defaults_for_timestamp',
            self::TIMESTAMP_AUTO_UPDATE_COLUMNS,
            implode(', ', $columns),
        );
    }
}
