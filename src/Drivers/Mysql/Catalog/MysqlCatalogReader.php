<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\Canonical\CatalogCanonicalizer;
use Pushery\SQLens\Catalog\Canonical\IdentifierFolding;
use Pushery\SQLens\Catalog\Canonical\ReferentialAction;
use Pushery\SQLens\Catalog\CatalogContext;
use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Catalog\Degradation\DatabaseErrorTranslator;
use Pushery\SQLens\Catalog\Degradation\PrivilegeProbe;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Catalog\SchemaScope;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Catalog\TableMembers;
use Pushery\SQLens\Catalog\TablePrefix;
use Pushery\SQLens\Catalog\Understanding\IndexComprehension;
use Pushery\SQLens\Catalog\Usage\IndexUsageReading;
use Pushery\SQLens\Contracts\CatalogPrivileges;
use Pushery\SQLens\Contracts\CatalogReader;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * Reads a live MySQL schema out of `information_schema`, into the same shape the PostgreSQL reader
 * produces — so one rule runs on both.
 *
 * ## Why `information_schema` here and `pg_catalog` there
 *
 * Not inconsistency. MySQL has no second, richer catalog to prefer: since 8.0 the
 * `information_schema` views ARE the data dictionary rather than a compatibility layer over one, and
 * they carry the things this package needs — `IS_VISIBLE` for an invisible index, `EXTRA` for a
 * generated column, `ENFORCED` for a check constraint. PostgreSQL is the engine where the standard
 * views throw away what matters, so each driver reads the source that answers.
 *
 * ## Three shapes measured here that the reader had to be built around
 *
 * - **`PRIMARY` is not a unique name.** Every table's primary key is called `PRIMARY`, so constraint
 *   identity is (table, name) and never the name alone. A reader keyed on the name would report one
 *   primary key for a database that has hundreds.
 * - **A view has no engine and no collation** — both come back NULL — so those attributes are
 *   absent on a view rather than stored as an empty string that later reads like a real value.
 * - **Index direction lives in `STATISTICS.COLLATION`**, as `A` or `D`. It is not a collation at
 *   all despite the column name, and a reader that skipped it would report a descending index as an
 *   ascending one.
 *
 * ## Extension filtering is a NAMED non-case here
 *
 * `CatalogRequest::$includeExtensionObjects` and `$allowedExtensions` have no effect on this driver,
 * and that is a fact about MySQL rather than a gap in the reader. A MySQL plugin or component is
 * server code — it owns no catalog objects, and `information_schema` records no ownership edge that
 * could be filtered on. PostgreSQL's `pg_depend` has no counterpart. An empty filter class here
 * would be a decoration that reads like a working control; stating the non-case is what keeps the
 * two drivers honest about being differently shaped rather than differently complete.
 *
 * ## The scope filter is not an optimization
 *
 * Every query is bound to the requested schemas. On an instance with many databases,
 * `information_schema` without a filter is a full scan of the data dictionary — the audit would
 * become the load it was sent to look for, and it would read databases it was never asked about.
 */
final readonly class MysqlCatalogReader implements CatalogReader
{
    /**
     * MySQL's own bookkeeping databases, never part of a reading.
     *
     * MySQL draws no schema/database distinction — a database IS the schema — so the server's own
     * four are exactly the ones a project must never be judged on.
     */
    private const array SYSTEM_SCHEMAS = ['information_schema', 'mysql', 'performance_schema', 'sys'];

    /**
     * The context every object read here carries, stamped with the connection it was read from.
     *
     * Assigned rather than promoted so the instance is attached ONCE, at construction, instead of
     * at each of the several places that build a SchemaObject — one of which would eventually be
     * added without it, and a finding that named no instance would look exactly like one whose
     * instance happened to be the driver name.
     */
    private SubjectContext $subjectContext;

    public function __construct(
        private ReaderSession $session,
        SubjectContext $subjectContext,
        private ?CatalogCanonicalizer $canonicalizer = null,
        private CatalogPrivileges $privileges = new MysqlCatalogPrivileges,
    ) {
        $this->subjectContext = $subjectContext->withConnection($session->instance());
    }

    /**
     * The object types this reader constructs — asserted here so a caller can read the scope.
     *
     * Ordered as the catalog is walked rather than alphabetically, because that is the order a reader
     * of {@see read()} meets them and a list that agrees with the code is one less thing to check.
     *
     * `information_schema` exposes EVENTS as well, and it is not read here, so `Event` does not
     * appear above — it needs an enum case that does not exist yet, and it brings the timestamp
     * noise that makes it its own piece of work rather than a line added below. TRIGGERS IS read.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function readableObjectTypes(): array
    {
        return [
            SchemaObjectType::Table,
            SchemaObjectType::View,
            SchemaObjectType::Column,
            SchemaObjectType::Index,
            SchemaObjectType::Constraint,
            SchemaObjectType::Collation,
            SchemaObjectType::Routine,
            SchemaObjectType::Trigger,
            SchemaObjectType::Event,
        ];
    }

    public function read(CatalogRequest $request): CatalogSnapshot
    {
        $startedAt = hrtime(true);

        return $this->session->read(function (Connection $reader) use ($request, $startedAt): CatalogSnapshot {
            // The folding rule is READ from the server rather than assumed. `lower_case_table_names`
            // has three values and a platform-dependent default; a reader that guessed would report
            // every table as renamed the first time it ran on another operating system.
            $canonicalizer = $this->canonicalizer ?? new CatalogCanonicalizer(
                IdentifierFolding::forLowerCaseTableNames((int) $this->scalar($reader, 'SELECT @@GLOBAL.lower_case_table_names AS v')),
            );

            $schemas = new SchemaScope($request->schemas, self::SYSTEM_SCHEMAS)
                ->apply([$this->scalar($reader, 'SELECT DATABASE() AS v')], $this->existingSchemas($reader));

            $context = CatalogContext::of(
                'mysql',
                $this->scalar($reader, 'SELECT VERSION() AS v'),
                $this->resolvedServerVersion($reader),
                $schemas,
                $request->tablePrefix,
            );

            // Asked BEFORE the reading, not inferred from it afterwards. MySQL FILTERS
            // information_schema by privilege without a word, so an under-privileged reading
            // succeeds and comes back empty — a clean, complete-looking audit of a database the
            // reader could not see. Nothing after the fact distinguishes that from a bare database.
            $skips = new PrivilegeProbe($this->privileges)->run($reader, $schemas);
            $objects = [];

            foreach ($this->tables($reader, $schemas) as $row) {
                $isView = $this->str($row, 'table_type') === 'VIEW';
                $type = $isView ? SchemaObjectType::View : SchemaObjectType::Table;

                if (! $request->wants($type)) {
                    continue;
                }

                $objects[] = new SchemaObject(
                    $type,
                    $canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'name')),
                    $canonicalizer->name($this->str($row, 'schema')),
                    // A view has no engine and no collation — both come back NULL — so the keys are
                    // absent rather than empty, and a rule asking about the engine of a view gets
                    // "nothing here" instead of a value it would have to second-guess.
                    array_filter([
                        'engine' => $this->nullableStr($row, 'engine'),
                        'collation' => $canonicalizer->collation($this->nullableStr($row, 'collation')),
                        // JOINED from information_schema.COLLATIONS rather than sliced off the front
                        // of the collation name. The naming convention holds, but a rule that has to
                        // trust a convention is a rule that is wrong the day an engine breaks it —
                        // and `binary` already does not follow it.
                        'charset' => $canonicalizer->collation($this->nullableStr($row, 'charset')),
                        'row_format' => $this->nullableStr($row, 'row_format'),
                        'comment' => $this->tableComment($this->nullableStr($row, 'comment'), $isView),
                    ], static fn (?string $value): bool => $value !== null),
                    $this->subjectContext,
                );
            }

            if ($request->wants(SchemaObjectType::Collation)) {
                foreach ($this->schemaDefaults($reader, $schemas, $canonicalizer) as $object) {
                    $objects[] = $object;
                }
            }

            foreach ([
                [SchemaObjectType::Column, $this->columns(...)],
                [SchemaObjectType::Index, $this->indexes(...)],
                [SchemaObjectType::Constraint, $this->constraints(...)],
            ] as [$type, $query]) {
                if (! $request->wants($type)) {
                    continue;
                }

                // A battery that fails becomes a named skip and the reading continues; the shared
                // helper is what keeps the two drivers from drifting apart on that.
                $read = DatabaseErrorTranslator::attempt(
                    static fn (): array => $query($reader, $schemas, $canonicalizer),
                    $type,
                    $type->value.'s',
                    $skips,
                );

                foreach ($read as $object) {
                    $objects[] = $object;
                }
            }

            // Beside the battery rather than inside it, because this reading NAMES what it could not
            // read: a routine whose body `information_schema` blanks becomes a skip of its own, and
            // the battery's uniform three-argument shape has no room to hand that back.
            if ($request->wants(SchemaObjectType::Routine)) {
                $read = DatabaseErrorTranslator::attempt(
                    function () use ($reader, $schemas, $canonicalizer, &$skips): array {
                        return $this->routines($reader, $schemas, $canonicalizer, $skips);
                    },
                    SchemaObjectType::Routine,
                    'routines',
                    $skips,
                );

                foreach ($read as $object) {
                    $objects[] = $object;
                }
            }

            if ($request->wants(SchemaObjectType::Trigger)) {
                foreach ($this->triggers($reader, $schemas, $canonicalizer) as $object) {
                    $objects[] = $object;
                }
            }

            if ($request->wants(SchemaObjectType::Event)) {
                foreach ($this->events($reader, $schemas, $canonicalizer) as $object) {
                    $objects[] = $object;
                }
            }

            $objects = new TablePrefix($request->tablePrefix, $request->prefixScope)->applyTo($objects, $skips);
            $objects = IndexComprehension::classify($objects, $skips);

            // LAST, because it reads the comprehension verdict the line above writes: a rule asking
            // which indexes could cover a foreign key must not be handed one nobody can compare.
            $objects = TableMembers::attachTo($objects);

            // The whole-reading budget, checked once at the end. Exceeding it is a NAMED
            // undetermined and not an abort: the objects already read are worth having, and killing
            // the run would throw them away to report a problem the run itself caused.
            $elapsedMs = (int) ((hrtime(true) - $startedAt) / 1_000_000);

            if ($elapsedMs > $this->session->readBudgetMs()) {
                $skips[] = CatalogSkip::for(
                    SchemaObjectType::Table,
                    'the catalog reading',
                    SkipReason::BudgetExceeded,
                    sprintf('the reading took %dms, over the %dms budget', $elapsedMs, $this->session->readBudgetMs()),
                );
            }

            return new CatalogSnapshot($context, $objects, $skips);
        });
    }

    /**
     * How often each index has been read — from `performance_schema`, which may be switched off.
     *
     * MySQL keeps these counters in `performance_schema.table_io_waits_summary_by_index_usage`, and
     * that instrument is a SERVER SETTING: an instance with `performance_schema = OFF` answers
     * nothing at all. So an empty reading here is genuinely ambiguous in a way PostgreSQL's is not,
     * and the unavailable answer is the common case rather than the exotic one.
     *
     * There is no counterpart to `pg_stat_database.stats_reset`: the counters run from server start
     * and MySQL records no reset point of its own. So the window is reported as unknown, and a rule
     * that needs one has to say so rather than assume the counters have been running long enough.
     * Reporting a made-up window would be worse than reporting none.
     */
    public function indexUsage(CatalogRequest $request): IndexUsageReading
    {
        return $this->session->read(function (Connection $reader) use ($request): IndexUsageReading {
            $canonicalizer = $this->canonicalizer ?? new CatalogCanonicalizer(IdentifierFolding::Preserve);

            try {
                // The SCOPE resolution is inside the try as well, and that placement was a defect
                // until a test caught it: those queries read the catalog too, and a failure there
                // escaped the accessor and took the whole audit down — over a set of counters that
                // were never essential to it.
                $schemas = new SchemaScope($request->schemas, self::SYSTEM_SCHEMAS)
                    ->apply([$this->scalar($reader, 'SELECT DATABASE() AS v')], $this->existingSchemas($reader));

                $rows = $this->rows($reader, <<<'SQL'
                    SELECT OBJECT_SCHEMA AS `schema`,
                           OBJECT_NAME   AS relation,
                           INDEX_NAME    AS `name`,
                           COUNT_STAR    AS scans
                    FROM performance_schema.table_io_waits_summary_by_index_usage
                    WHERE OBJECT_SCHEMA IN (SCHEMA_LIST) AND INDEX_NAME IS NOT NULL
                    ORDER BY OBJECT_SCHEMA, OBJECT_NAME, INDEX_NAME
                    SQL, $schemas);
            } catch (Throwable) {
                // performance_schema off, or not readable by this role. Named rather than returned
                // as an empty reading: "no index has been used" and "nobody could look" are
                // different statements and only one of them is a finding.
                return IndexUsageReading::unavailable();
            }

            $scans = [];

            foreach ($rows as $row) {
                // Keyed by the index's qualified name the catalog reader produces — schema, table,
                // index — because MySQL names an index by its TABLE and a schema-only key would
                // collide across tables that both call an index `idx_created`.
                $relation = $canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'relation'));
                $scans[$relation.'.'.$canonicalizer->name($this->str($row, 'name'))] = (int) ($row['scans'] ?? 0);
            }

            // No stats_reset counterpart exists on this engine, so the window start is unknown and
            // stays unknown. A rule needing one must say so.
            return new IndexUsageReading($scans);
        });
    }

    /**
     * A table's comment, or null when it has none — and MySQL makes that harder than it sounds.
     *
     * Two normalizations, both measured against 8.4.10, and both silent failures without them:
     *
     * - **An absent comment is the EMPTY STRING here**, where PostgreSQL returns NULL. Passing it
     *   through would make every undocumented table look documented with a zero-length description.
     * - **A VIEW carries the literal word `VIEW` in `TABLE_COMMENT`.** Not a comment somebody wrote
     *   — the server puts it there:
     *
     *   ```
     *   SELECT TABLE_NAME, TABLE_COMMENT FROM information_schema.TABLES;
     *     no_c    →  ''
     *     v       →  'VIEW'
     *     with_c  →  'documented'
     *   ```
     *
     *   A rule reading that as documentation would report every view in every schema as documented,
     *   in the direction nobody checks. So it is discarded FOR A VIEW ONLY: a table genuinely
     *   commented `VIEW` — odd, but a person's choice — keeps its comment.
     */
    private function tableComment(?string $raw, bool $isView): ?string
    {
        if ($raw === null || trim($raw) === '') {
            return null;
        }

        return $isView && $raw === 'VIEW' ? null : $raw;
    }

    /**
     * @param  list<string>  $schemas
     * @return list<array<string, scalar|null>>
     */
    private function tables(Connection $reader, array $schemas): array
    {
        return $this->rows($reader, <<<'SQL'
            SELECT t.TABLE_SCHEMA      AS `schema`,
                   t.TABLE_NAME        AS `name`,
                   t.TABLE_TYPE        AS table_type,
                   t.ENGINE            AS engine,
                   t.TABLE_COLLATION   AS collation,
                   c.CHARACTER_SET_NAME AS charset,
                   t.ROW_FORMAT        AS row_format,
                   t.TABLE_COMMENT     AS `comment`
            FROM information_schema.TABLES t
            LEFT JOIN information_schema.COLLATIONS c ON c.COLLATION_NAME = t.TABLE_COLLATION
            WHERE t.TABLE_SCHEMA IN (SCHEMA_LIST)
            ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME
            SQL, $schemas);
    }

    /**
     * The character set and collation each database in scope hands to anything created without one.
     *
     * ## Why this is read at all, when every table already carries its own
     *
     * Because the database default is what the NEXT table inherits. A schema whose tables are all
     * `utf8mb4` while the database itself defaults to `latin1` is one hand-written `CREATE TABLE`
     * away from a column that silently cannot hold an emoji — and nothing in the tables already
     * present says so. The fact is invisible exactly where it does its damage, which is the argument
     * for reading it.
     *
     * ## Why it travels as a Collation object
     *
     * {@see SchemaObjectType::Collation} is documented as "a collation, database-wide or explicitly
     * created", and a database-wide collation is precisely what this is. The PostgreSQL reader
     * produces the same type for the same scope; the attributes differ because the two engines hold
     * different facts about it — MySQL has no collation-version drift to record, and inventing empty
     * version attributes to look symmetrical would be a shape without a meaning behind it.
     *
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function schemaDefaults(Connection $reader, array $schemas, CatalogCanonicalizer $canonicalizer): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT SCHEMA_NAME                AS `name`,
                   DEFAULT_CHARACTER_SET_NAME AS charset,
                   DEFAULT_COLLATION_NAME     AS collation
            FROM information_schema.SCHEMATA
            WHERE SCHEMA_NAME IN (SCHEMA_LIST)
            ORDER BY SCHEMA_NAME
            SQL, $schemas);

        return array_map(fn (array $row): SchemaObject => new SchemaObject(
            SchemaObjectType::Collation,
            $canonicalizer->name($this->str($row, 'name')),
            // No parent. A database default belongs to nothing above it, and naming the database as
            // its own parent would make the object look like a member of itself.
            null,
            array_filter([
                'collation_scope' => 'database',
                'charset' => $canonicalizer->collation($this->nullableStr($row, 'charset')),
                'collation' => $canonicalizer->collation($this->nullableStr($row, 'collation')),
            ], static fn (?string $value): bool => $value !== null),
            $this->subjectContext,
        ), $rows);
    }

    /**
     * The triggers on tables in scope, keyed by the table they hang on.
     *
     * ## The identity is the PAIR
     *
     * A trigger name is unique per table rather than per schema, so two tables may each carry an
     * `audit_row` and they are two objects. Keying on the name alone folds them into one whose
     * attributes appear to change with the reading order — drift reported on an unchanged database,
     * which is the failure this suite exists to not have. Argued once on the PostgreSQL side too;
     * the shape of the identity is a property of triggers, not of an engine.
     *
     * ## Here the body IS the object, unlike PostgreSQL
     *
     * MySQL stores the action statement inline, so `ACTION_STATEMENT` is what drifts. PostgreSQL's
     * trigger only names a function and its body is compared separately as a routine. The two
     * engines therefore carry different attributes for the same object type, and that is honest
     * rather than untidy: pretending to a shared shape would mean inventing a value on one side.
     *
     * ## `ACTION_ORDER` is compared, and it is not cosmetic
     *
     * MySQL 8.0 made trigger order explicit with `FOLLOWS` and `PRECEDES`. Two triggers whose order
     * is swapped are a different database — the second one sees what the first one wrote — so the
     * order is observable behavior and belongs in the fingerprint.
     *
     * The action statement goes through the SHARED canonicalizer for the reasons argued at
     * {@see CatalogCanonicalizer::routineBody()}. A second normalizer that may disagree with the
     * first about where a body ends is the same defect in green.
     *
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function triggers(Connection $reader, array $schemas, CatalogCanonicalizer $canonicalizer): array
    {
        $rows = $this->rows($reader, <<<'SQL_WRAP'
        SELECT TRIGGER_SCHEMA     AS `schema`,
               TRIGGER_NAME       AS `name`,
               EVENT_OBJECT_TABLE AS table_name,
               ACTION_TIMING      AS timing,
               EVENT_MANIPULATION AS event,
               ACTION_ORIENTATION AS orientation,
               ACTION_ORDER       AS action_order,
               ACTION_STATEMENT   AS statement
        FROM information_schema.TRIGGERS
        WHERE TRIGGER_SCHEMA IN (SCHEMA_LIST)
        ORDER BY TRIGGER_SCHEMA, EVENT_OBJECT_TABLE, ACTION_ORDER, TRIGGER_NAME
        SQL_WRAP, $schemas);

        $triggers = [];

        foreach ($rows as $row) {
            $schema = $this->str($row, 'schema');
            $table = $this->str($row, 'table_name');

            $qualified = $canonicalizer->qualified($schema, $table).'.'.$canonicalizer->name($this->str($row, 'name'));

            $triggers[] = new SchemaObject(
                SchemaObjectType::Trigger,
                $qualified,
                $canonicalizer->name($schema),
                [
                    'timing' => mb_strtolower($this->str($row, 'timing')),
                    'event' => mb_strtolower($this->str($row, 'event')),
                    'orientation' => mb_strtolower($this->str($row, 'orientation')),
                    'action_order' => $this->str($row, 'action_order'),
                    'statement' => $canonicalizer->routineBody($this->str($row, 'statement')),
                ],
                $this->subjectContext,
            );
        }

        return $triggers;
    }

    /**
     * Every scheduled event in scope — the one object type PostgreSQL has no answer for.
     *
     * ## Four of this table's columns are read and then deliberately not compared
     *
     * `information_schema.EVENTS` mixes the schedule with the schedule's HISTORY, and the history
     * moves without anybody touching the database. `LAST_EXECUTED` advances on every run; `STARTS`
     * silently inherits the creation timestamp when the declaration omits it. Both are read — a
     * report showing when an event last ran is useful — and both are registered in
     * {@see CatalogObjectFingerprint::VOLATILE_ATTRIBUTES} so no comparison reads them.
     *
     * ## `status` and `execution_status` are two names for two different facts
     *
     * A RECURRING event that is DISABLED was disabled by somebody, and that is drift worth
     * reporting. A ONE TIME event declared `ON COMPLETION PRESERVE` sets itself to DISABLED the
     * instant it fires — measured on 8.4.10 — and that is the event working.
     *
     * The same word, two meanings, so two attribute names: only `execution_status` is volatile. A
     * single `status` would have forced a choice between reporting drift nobody caused and hiding a
     * deliberate `ALTER EVENT ... DISABLE`.
     *
     * `CREATED`, `LAST_ALTERED` and `ORIGINATOR` are not read at all. They describe when and by
     * which server the row was written, which is not a property of the schema — the same line the
     * trigger reader above draws.
     *
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function events(Connection $reader, array $schemas, CatalogCanonicalizer $canonicalizer): array
    {
        $rows = $this->rows($reader, <<<'SQL_WRAP'
        SELECT EVENT_SCHEMA     AS `schema`,
               EVENT_NAME       AS `name`,
               EVENT_TYPE       AS event_type,
               EXECUTE_AT       AS execute_at,
               INTERVAL_VALUE   AS interval_value,
               INTERVAL_FIELD   AS interval_field,
               STARTS           AS starts,
               ENDS             AS ends,
               STATUS           AS status,
               ON_COMPLETION    AS on_completion,
               TIME_ZONE        AS time_zone,
               SQL_MODE         AS sql_mode,
               LAST_EXECUTED    AS last_executed,
               EVENT_DEFINITION AS definition
        FROM information_schema.EVENTS
        WHERE EVENT_SCHEMA IN (SCHEMA_LIST)
        ORDER BY EVENT_SCHEMA, EVENT_NAME
        SQL_WRAP, $schemas);

        $events = [];

        foreach ($rows as $row) {
            $schema = $this->str($row, 'schema');

            // ONE TIME / RECURRING, as MySQL spells it. It decides which of the two status names the
            // reading uses, so it is normalized once here rather than compared as free text.
            $recurring = mb_strtolower($this->str($row, 'event_type')) === 'recurring';
            $status = mb_strtolower($this->str($row, 'status'));

            $events[] = new SchemaObject(
                SchemaObjectType::Event,
                $canonicalizer->qualified($schema, $this->str($row, 'name')),
                $canonicalizer->name($schema),
                array_filter([
                    'event_type' => $recurring ? 'recurring' : 'one_time',
                    // Absent rather than null on the side that does not have them: a recurring event
                    // has no EXECUTE_AT and a one-shot has no interval, and a key that is missing
                    // reads as "nothing here" instead of a value a rule would have to second-guess.
                    'execute_at' => $this->nullableStr($row, 'execute_at'),
                    'interval_value' => $this->nullableStr($row, 'interval_value'),
                    'interval_field' => $this->lowered($this->nullableStr($row, 'interval_field')),
                    // ENDS is never implied — NULL when undeclared — so unlike STARTS it is always
                    // something somebody wrote, and it is compared.
                    'ends' => $this->nullableStr($row, 'ends'),
                    'status' => $recurring ? $status : null,
                    'execution_status' => $recurring ? null : $status,
                    'on_completion' => mb_strtolower($this->str($row, 'on_completion')),
                    'time_zone' => $this->str($row, 'time_zone'),
                    'sql_mode' => $this->str($row, 'sql_mode'),
                    'starts' => $this->nullableStr($row, 'starts'),
                    'last_executed' => $this->nullableStr($row, 'last_executed'),
                ], static fn (?string $value): bool => $value !== null),
                $this->subjectContext,
            );
        }

        return $events;
    }

    /** Lower-cases a value MySQL spells in capitals, without inventing one where there is none. */
    private function lowered(?string $value): ?string
    {
        return $value === null ? null : mb_strtolower($value);
    }

    /**
     * Every stored function and procedure in scope, with a body that compares.
     *
     * ## The key needs no argument list, unlike PostgreSQL's
     *
     * MySQL does not overload: a schema plus a name identifies a routine, and `CREATE PROCEDURE` on
     * an existing name is an error rather than a second routine. So the qualified name is the whole
     * identity here, while the PostgreSQL reader has to carry the identity arguments in its key.
     * Two engines, two correct answers — not an inconsistency to reconcile.
     *
     * ## Three columns are read and deliberately NOT compared
     *
     * `CREATED` and `LAST_ALTERED` are timestamps, so they differ between the live database and a
     * replay by construction. They are not listed under `VOLATILE_ATTRIBUTES`, they are simply never
     * selected — a value that never enters an attribute map cannot leak out of one, and the volatile
     * list is for fields a rule genuinely wants to read.
     *
     * `DEFINER` is the sharper trap, because it looks like schema and is not. It records the account
     * that ran the CREATE, so a replay executed as a different user would report **every** routine as
     * divergent — a fact about who ran the migration, never about what the migration says.
     *
     * `SQL_MODE` is the same shape of mistake one level down: it freezes the session mode at creation
     * time, so a replay under a different client setting diverges on every routine at once. It does
     * change semantics, which is why the omission is stated here rather than left to be noticed — a
     * check on the mode belongs to a rule about the CONNECTION, not to a schema comparison.
     *
     * ## The body
     *
     * `ROUTINE_DEFINITION` is the stored text, with no reconstruction — MySQL has no counterpart to
     * `pg_get_functiondef()`. It goes through the same {@see CatalogCanonicalizer::routineBody()} as
     * the PostgreSQL side, so the two engines cannot drift apart on what "the same body" means.
     *
     * It also comes back NULL for a routine the reader may see but not read the source of, and that
     * state is ordinary rather than exotic. Measured against MySQL 8.4, three privilege sets and three
     * different answers:
     *
     *     SELECT only                       → the row is not visible at all
     *     SELECT + EXECUTE                  → the row IS visible, ROUTINE_DEFINITION is NULL
     *     SELECT + EXECUTE + SHOW_ROUTINE   → the definition comes back
     *
     * The middle one is where an ordinary application role lands: `EXECUTE` is granted so the app can
     * call the function, and `SHOW_ROUTINE` is a separate GLOBAL privilege nobody grants by accident.
     *
     * So it is reported as a named skip that says which grant is missing — never compared as an empty
     * body. Comparing it would be worse than silence: drift reads the live database against a replay
     * of the migrations, so an unreadable body would come back `''` on one side and real SQL on the
     * other, and every routine in the project would be reported as divergent at once. The finding
     * would say "somebody changed this" when the truth is "we were not allowed to look".
     *
     * @param  list<string>  $schemas
     * @param  list<CatalogSkip>  $skips  appended to for every routine whose source is unreadable
     * @return list<SchemaObject>
     */
    private function routines(Connection $reader, array $schemas, CatalogCanonicalizer $canonicalizer, array &$skips): array
    {
        $rows = $this->rows($reader, <<<'SQL_WRAP'
        SELECT ROUTINE_SCHEMA      AS `schema`,
               ROUTINE_NAME        AS `name`,
               ROUTINE_TYPE        AS kind,
               ROUTINE_BODY        AS body_language,
               EXTERNAL_LANGUAGE   AS external_language,
               DTD_IDENTIFIER      AS result,
               IS_DETERMINISTIC    AS is_deterministic,
               SQL_DATA_ACCESS     AS data_access,
               SECURITY_TYPE       AS security_type,
               ROUTINE_DEFINITION  AS body
        FROM information_schema.ROUTINES
        WHERE ROUTINE_SCHEMA IN (SCHEMA_LIST)
        ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME
        SQL_WRAP, $schemas);

        $routines = [];

        foreach ($rows as $row) {
            $qualified = $canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'name'));
            $body = $this->nullableStr($row, 'body');

            if ($body === null) {
                $skips[] = CatalogSkip::for(
                    SchemaObjectType::Routine,
                    $qualified,
                    SkipReason::InsufficientPrivilege,
                    'information_schema lists the routine but blanks ROUTINE_DEFINITION, so its body '
                    .'cannot be compared. Grant this account SHOW_ROUTINE, or exclude the routine.',
                );

                continue;
            }

            $language = $this->str($row, 'body_language');

            $routines[] = new SchemaObject(
                SchemaObjectType::Routine,
                $qualified,
                $canonicalizer->name($this->str($row, 'schema')),
                array_filter([
                    // Spelled out in the DRIVER, as on the PostgreSQL side: the core stays free of
                    // engine vocabulary, and a report reads better for it.
                    'routine_kind' => $this->str($row, 'kind') === 'PROCEDURE' ? 'procedure' : 'function',
                    'language' => mb_strtolower($language === 'SQL' ? $language : $this->str($row, 'external_language')),
                    // A procedure returns nothing, and MySQL says so with NULL rather than an empty
                    // string. The key is absent instead of blank, so a rule asking about the result
                    // type of a procedure gets "nothing here" rather than a value to second-guess —
                    // the same shape as the engine and collation of a view above.
                    'result' => $this->nullableStr($row, 'result'),
                    'deterministic' => $this->str($row, 'is_deterministic') === 'YES' ? 'yes' : 'no',
                    'data_access' => mb_strtolower($this->str($row, 'data_access')),
                    'security_definer' => $this->str($row, 'security_type') === 'DEFINER' ? 'yes' : 'no',
                    'body' => $canonicalizer->routineBody($body),
                ], static fn (?string $value): bool => $value !== null),
                $this->subjectContext,
            );
        }

        return $routines;
    }

    /**
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function columns(Connection $reader, array $schemas, CatalogCanonicalizer $canonicalizer): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT TABLE_SCHEMA           AS `schema`,
                   TABLE_NAME             AS relation,
                   COLUMN_NAME            AS `name`,
                   COLUMN_TYPE            AS raw_type,
                   IS_NULLABLE            AS is_nullable,
                   COLUMN_DEFAULT         AS column_default,
                   EXTRA                  AS extra,
                   GENERATION_EXPRESSION  AS generation_expression,
                   COLLATION_NAME         AS collation,
                   COLUMN_COMMENT         AS `comment`,
                   CHARACTER_SET_NAME     AS charset,
                   CHARACTER_MAXIMUM_LENGTH AS max_length,
                   NUMERIC_PRECISION      AS numeric_precision,
                   NUMERIC_SCALE          AS numeric_scale
            FROM information_schema.COLUMNS
            WHERE TABLE_SCHEMA IN (SCHEMA_LIST)
            ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION
            SQL, $schemas);

        return array_map(function (array $row) use ($canonicalizer): SchemaObject {
            $relation = $canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'relation'));
            $extra = $this->str($row, 'extra');
            $type = $canonicalizer->type(
                $this->str($row, 'raw_type'),
                $this->nullableInt($row, 'max_length'),
                $this->nullableInt($row, 'numeric_precision'),
                $this->nullableInt($row, 'numeric_scale'),
            );

            return new SchemaObject(
                SchemaObjectType::Column,
                $relation.'.'.$canonicalizer->name($this->str($row, 'name')),
                $relation,
                [
                    'type' => $type->name,
                    'raw_type' => $type->raw,
                    // Empty rather than NULL when absent, like the table's — normalized to one shape
                    // so a rule does not have to know which engine it is reading.
                    'comment' => ($c = trim((string) $this->nullableStr($row, 'comment'))) === '' ? null : $c,
                    'unsigned' => $type->unsigned,
                    'not_null' => $this->str($row, 'is_nullable') === 'NO',
                    'default' => $canonicalizer->defaultExpression($this->nullableStr($row, 'column_default')),
                    // MySQL packs several unrelated facts into EXTRA. They are read out here rather
                    // than left as one string, because a rule asking "is this generated?" should not
                    // have to parse a field that also says `auto_increment` and `DEFAULT_GENERATED`.
                    //
                    // `auto_increments`, NOT `auto_increment`, and the extra letter is a defect fix.
                    // The volatile register drops the attribute named `auto_increment` on the
                    // grounds that it is "MySQL's next value for the table" — a counter that moves
                    // on every insert. That counter is read NOWHERE in this package. What the name
                    // collided with was this: a boolean saying whether the column auto-increments,
                    // which is a genuine schema fact. So a column that gained or lost AUTO_INCREMENT
                    // was invisible to the drift comparison — measured, and losing it on a primary
                    // key is the moment inserts start failing.
                    'auto_increments' => str_contains($extra, 'auto_increment'),
                    'generated' => str_contains($extra, 'GENERATED') && ! str_contains($extra, 'DEFAULT_GENERATED'),
                    'generation_expression' => $this->nullableStr($row, 'generation_expression'),
                    'collation' => $canonicalizer->collation($this->nullableStr($row, 'collation')),
                    // NULL on every non-character column — a BLOB, an INT, a DATE. Kept as null
                    // rather than folded to '' so a rule can tell "this column has no character set
                    // because it holds no characters" from "the reading did not learn one".
                    'charset' => $canonicalizer->collation($this->nullableStr($row, 'charset')),
                ],
                $this->subjectContext,
            );
        }, $rows);
    }

    /**
     * Indexes, folded from one row per COLUMN into one object per index.
     *
     * `STATISTICS` is a per-column view — a three-column index is three rows — so a reader that
     * mapped rows to objects would report three indexes where there is one, and every rule counting
     * indexes would be wrong by a factor nobody could predict.
     *
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function indexes(Connection $reader, array $schemas, CatalogCanonicalizer $canonicalizer): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT TABLE_SCHEMA  AS `schema`,
                   TABLE_NAME    AS relation,
                   INDEX_NAME    AS `name`,
                   NON_UNIQUE    AS non_unique,
                   SEQ_IN_INDEX  AS seq,
                   COLUMN_NAME   AS column_name,
                   COLLATION     AS direction,
                   INDEX_TYPE    AS index_type,
                   IS_VISIBLE    AS is_visible,
                   -- The PREFIX LENGTH, and it is not a detail: `KEY (email(20))` indexes the first
                   -- 20 bytes, not the column, and reports the column name exactly as a full-column
                   -- key does. A reader that skipped this would hand a redundancy rule two indexes
                   -- it cannot tell apart, and the rule would advise dropping the wrong one.
                   SUB_PART      AS sub_part,
                   EXPRESSION    AS expression
            FROM information_schema.STATISTICS
            WHERE TABLE_SCHEMA IN (SCHEMA_LIST)
            ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
            SQL, $schemas);

        /** @var array<string, array{row: array<string, scalar|null>, columns: list<array{name: string, descending: bool}>, functional: bool, prefixed: bool}> $grouped */
        $grouped = [];

        foreach ($rows as $row) {
            $key = $this->str($row, 'schema').'.'.$this->str($row, 'relation').'.'.$this->str($row, 'name');

            $grouped[$key] ??= ['row' => $row, 'columns' => [], 'functional' => false, 'prefixed' => false];

            if ($this->nullableInt($row, 'sub_part') !== null) {
                // ANY prefixed column makes the whole index one this package will not compare: a
                // key over the first 20 bytes of a column answers a different question from a key
                // over the column, and the two are indistinguishable by name alone.
                $grouped[$key]['prefixed'] = true;
            }

            $column = $this->nullableStr($row, 'column_name');

            if ($column === null) {
                // A functional index has no column name and an EXPRESSION instead. Recorded as a
                // fact rather than guessed at: a redundancy heuristic that treated an expression
                // index as a plain one would be wrong about the one index kind it cannot read.
                $grouped[$key]['functional'] = true;

                continue;
            }

            $grouped[$key]['columns'][] = [
                'name' => $column,
                // Despite the column being called COLLATION, this is the sort DIRECTION: A or D.
                'descending' => $this->str($row, 'direction') === 'D',
            ];
        }

        return array_values(array_map(function (array $index) use ($canonicalizer): SchemaObject {
            $row = $index['row'];
            $relation = $canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'relation'));

            return new SchemaObject(
                SchemaObjectType::Index,
                $relation.'.'.$canonicalizer->name($this->str($row, 'name')),
                $relation,
                [
                    'method' => mb_strtolower($this->str($row, 'index_type')),
                    'unique' => $this->str($row, 'non_unique') === '0',
                    'primary' => $this->str($row, 'name') === 'PRIMARY',
                    // Always false, and STATED rather than left absent. MySQL has no counterpart to
                    // PostgreSQL's NULLS NOT DISTINCT — measured on 8.4: three rows sharing every
                    // other column, each with a NULL in one member, coexist under a UNIQUE KEY. An
                    // absent attribute would read as "unknown", and a rule would answer undetermined
                    // on every MySQL table over a question this engine settles the same way always.
                    'nulls_not_distinct' => false,
                    // MySQL has no INCLUDE payload at all — no covering-index syntax of any kind —
                    // so this is constantly false and STATED rather than left absent, for the same
                    // reason as the flag above: an absent attribute would read as "unknown".
                    'has_include' => false,
                    // Read from SUB_PART: an index over the first N bytes of a column, which reports
                    // the same column NAME as a full-column key. MySQL's own shape, with no
                    // PostgreSQL counterpart.
                    'prefixed_columns' => $index['prefixed'],
                    'columns' => $canonicalizer->indexColumns($index['columns']),
                    // Names only, in order — the shape a foreign-key coverage question compares
                    // against. `columns` above carries the sort direction, which is a different
                    // fact and would make an otherwise identical index look different across
                    // engines.
                    'key_columns' => implode(', ', array_map(
                        static fn (array $column): string => (string) $column['name'],
                        $index['columns'],
                    )),
                    'functional' => $index['functional'],
                    // An invisible index exists, costs writes, and the optimizer ignores it — a fact
                    // with no PostgreSQL counterpart and one a redundancy rule must not miss.
                    'visible' => $this->str($row, 'is_visible') !== 'NO',
                    'expression' => $this->nullableStr($row, 'expression'),
                ],
                $this->subjectContext,
            );
        }, $grouped));
    }

    /**
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function constraints(Connection $reader, array $schemas, CatalogCanonicalizer $canonicalizer): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT c.CONSTRAINT_SCHEMA  AS `schema`,
                   c.TABLE_NAME         AS relation,
                   c.CONSTRAINT_NAME    AS `name`,
                   c.CONSTRAINT_TYPE    AS constraint_type,
                   c.ENFORCED           AS enforced,
                   r.UPDATE_RULE        AS on_update,
                   r.DELETE_RULE        AS on_delete,
                   r.REFERENCED_TABLE_NAME AS referenced_table,
                   -- The constraint's own columns, in the order it declares them. A foreign key is
                   -- covered only by an index whose LEFT PREFIX is this list, so the order is the
                   -- fact rather than a detail — hence ORDER BY ORDINAL_POSITION and not by name.
                   (SELECT GROUP_CONCAT(u.COLUMN_NAME ORDER BY u.ORDINAL_POSITION SEPARATOR ', ')
                      FROM information_schema.KEY_COLUMN_USAGE u
                     WHERE u.CONSTRAINT_SCHEMA = c.CONSTRAINT_SCHEMA
                       AND u.CONSTRAINT_NAME = c.CONSTRAINT_NAME
                       AND u.TABLE_NAME = c.TABLE_NAME) AS key_columns,
                   -- The columns on the OTHER side, in the SAME order, so position n here pairs with
                   -- position n above. A rule comparing the two sides — their types, their
                   -- collations — has nothing to compare without it, and pairing by name would be
                   -- wrong the moment the two sides spell a column differently.
                   (SELECT GROUP_CONCAT(u.REFERENCED_COLUMN_NAME ORDER BY u.ORDINAL_POSITION SEPARATOR ', ')
                      FROM information_schema.KEY_COLUMN_USAGE u
                     WHERE u.CONSTRAINT_SCHEMA = c.CONSTRAINT_SCHEMA
                       AND u.CONSTRAINT_NAME = c.CONSTRAINT_NAME
                       AND u.TABLE_NAME = c.TABLE_NAME
                       AND u.REFERENCED_COLUMN_NAME IS NOT NULL) AS referenced_columns,
                   r.UNIQUE_CONSTRAINT_SCHEMA AS referenced_schema
            FROM information_schema.TABLE_CONSTRAINTS c
            LEFT JOIN information_schema.REFERENTIAL_CONSTRAINTS r
                   ON r.CONSTRAINT_SCHEMA = c.CONSTRAINT_SCHEMA
                  AND r.CONSTRAINT_NAME = c.CONSTRAINT_NAME
                  AND r.TABLE_NAME = c.TABLE_NAME
            WHERE c.CONSTRAINT_SCHEMA IN (SCHEMA_LIST)
            ORDER BY c.CONSTRAINT_SCHEMA, c.TABLE_NAME, c.CONSTRAINT_NAME
            SQL, $schemas);

        return array_map(function (array $row) use ($canonicalizer): SchemaObject {
            $relation = $canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'relation'));

            return new SchemaObject(
                SchemaObjectType::Constraint,
                // Qualified by its TABLE, not by its schema: every table's primary key is called
                // `PRIMARY`, so a name-keyed identity would report one primary key for a database
                // that has hundreds. Measured, on a two-table probe.
                $relation.'.'.$canonicalizer->name($this->str($row, 'name')),
                $relation,
                array_filter([
                    'constraint_type' => $this->str($row, 'constraint_type'),
                    'key_columns' => $this->str($row, 'key_columns'),
                    // MySQL can hold a CHECK constraint that is NOT ENFORCED — present, documented
                    // and doing nothing, which is the same shape as PostgreSQL's NOT VALID and just
                    // as invisible to anyone reading the schema.
                    'enforced' => $this->str($row, 'enforced') !== 'NO',
                    'on_update' => $this->referentialAction($row, 'on_update'),
                    'on_delete' => $this->referentialAction($row, 'on_delete'),
                    'referenced_table' => $this->nullableStr($row, 'referenced_table'),
                    // The same table again, qualified and canonicalized — the form a snapshot object
                    // is actually keyed by. `referenced_table` stays exactly as the server spelled
                    // it, because it is what a message quotes; this one is what a lookup joins on,
                    // and deriving it at each call site would put identifier folding in every rule
                    // that ever wants to follow an edge.
                    'referenced_relation' => $this->referencedRelation($row, $canonicalizer),
                    'referenced_columns' => $this->nullableStr($row, 'referenced_columns'),
                ], static fn (string|bool|null $value): bool => $value !== null),
                $this->subjectContext,
            );
        }, $rows);
    }

    /**
     * Every database this server has — the list a configured schema is checked against.
     *
     * `information_schema.SCHEMATA` shows only what the current user may see, and that is the right
     * list here: a database the reader cannot see is one it cannot audit, so reporting it as absent
     * is closer to the truth than returning an empty audit of it.
     *
     * @return list<string>
     */
    private function existingSchemas(Connection $reader): array
    {
        $rows = $this->rows(
            $reader,
            'SELECT SCHEMA_NAME AS schema_name FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME',
            [],
        );

        return array_map(fn (array $row): string => $this->str($row, 'schema_name'), $rows);
    }

    /**
     * The table a foreign key points at, qualified and folded the way snapshot objects are.
     *
     * Null when the constraint is not a foreign key, and null when the server named a table without
     * naming its schema — an edge nobody can follow is better reported as unfollowable than as one
     * pointing somewhere plausible.
     *
     * @param  array<string, scalar|null>  $row
     */
    private function referencedRelation(array $row, CatalogCanonicalizer $canonicalizer): ?string
    {
        $schema = $this->nullableStr($row, 'referenced_schema');
        $table = $this->nullableStr($row, 'referenced_table');

        return $schema === null || $table === null ? null : $canonicalizer->qualified($schema, $table);
    }

    /** @param  array<string, scalar|null>  $row */
    private function referentialAction(array $row, string $key): ?string
    {
        $raw = $this->nullableStr($row, $key);

        return $raw === null ? null : ReferentialAction::read($raw)->value;
    }

    private function resolvedServerVersion(Connection $reader): ResolvedServerVersion
    {
        $version = ServerVersion::parse($this->scalar($reader, 'SELECT VERSION() AS v'), 'mysql');

        return $version instanceof ServerVersion
            ? ResolvedServerVersion::detected($version)
            : ResolvedServerVersion::unresolvable();
    }

    /**
     * Run one catalog query with the schema scope bound in.
     *
     * The placeholder is expanded here rather than interpolated: `information_schema` without a
     * schema filter is a full scan of the data dictionary on an instance with many databases — the
     * audit would become the load it was sent to look for, and it would read databases nobody asked
     * about.
     *
     * ## `$sql` is typed `literal-string`, and that is enforcement rather than decoration
     *
     * This helper substitutes a placeholder run into a statement, so the statement itself must be
     * the author's own text — every caller in this class passes a constant, and until this line
     * said so, nothing checked it. PHPStan now refuses a caller that hands over anything a runtime
     * value could have reached, at the boundary rather than in review.
     *
     * It also completes a proof one layer up. The package's own injection rule reported this line:
     * with `$sql` opaque it could not tell a placeholder run from a value, and "a runtime value is
     * assembled into the text of this statement" was a claim about a shape it could not see. The
     * narrower type makes the claim decidable and the finding correctly disappears — the rule was
     * not loosened, the code stated what was already true of it.
     *
     * @param  literal-string  $sql
     * @param  list<string>  $schemas
     * @return list<array<string, scalar|null>>
     */
    #[RawSql(reason: 'information_schema catalog SQL with a variable-length IN (...). The template is typed literal-string so it is provably the package own text, and the schema names travel as bindings')]
    private function rows(Connection $reader, string $sql, array $schemas): array
    {
        // An empty scope must select nothing rather than everything. `IN ()` is a syntax error, so
        // a placeholder that can never match stands in — the failure direction that reads nothing
        // is the safe one for a reader that is not supposed to wander.
        $placeholders = $schemas === [] ? "''" : implode(', ', array_fill(0, count($schemas), '?'));

        $result = $reader->select(str_replace('SCHEMA_LIST', $placeholders, $sql), $schemas);

        $rows = [];

        foreach ($result as $row) {
            $narrowed = [];

            foreach ((array) $row as $key => $value) {
                $narrowed[(string) $key] = is_scalar($value) ? $value : null;
            }

            $rows[] = $narrowed;
        }

        return $rows;
    }

    /**
     * One scalar value from a one-row statement.
     *
     * `literal-string` for the same reason {@see rows()} carries it, and it propagated here on its
     * own: this method hands its argument straight through, so the promise it makes has to be the
     * promise it keeps. PHPStan pointed that out at the boundary the moment the stronger type went
     * on, which is what enforcement looks like from the inside.
     *
     * @param  literal-string  $sql
     */
    private function scalar(Connection $reader, string $sql): string
    {
        return $this->str($this->rows($reader, $sql, [])[0] ?? [], 'v');
    }

    /** @param  array<string, scalar|null>  $row */
    private function str(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /** @param  array<string, scalar|null>  $row */
    private function nullableStr(array $row, string $key): ?string
    {
        $value = $row[$key] ?? null;

        return is_scalar($value) ? (string) $value : null;
    }

    /** @param  array<string, scalar|null>  $row */
    private function nullableInt(array $row, string $key): ?int
    {
        $value = $row[$key] ?? null;

        return is_scalar($value) ? (int) $value : null;
    }

    /** Whether a throwable was this reader's own budget firing rather than a fault in the catalog. */
    public function isOwnTimeout(Throwable $error): bool
    {
        return $this->session->isOwnTimeout($error);
    }
}
