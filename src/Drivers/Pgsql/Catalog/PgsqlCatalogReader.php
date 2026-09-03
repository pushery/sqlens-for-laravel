<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

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
use Pushery\SQLens\Catalog\PartitionResolver;
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
 * Reads a live PostgreSQL schema out of `pg_catalog`.
 *
 * ## Why `pg_catalog` and not `information_schema`
 *
 * The standard views are a lossy projection of the catalog. They cannot express the things this
 * package most needs: whether an index is `indisvalid` (the corpse a canceled
 * `CREATE INDEX CONCURRENTLY` leaves behind), whether a constraint is `NOT VALID`, which access
 * method an index uses, what a partial index's predicate is. Reading them would mean building an
 * audit suite that is structurally blind to the deploy hazards it exists to find — and paying more
 * for the privilege, because those views are themselves joins over the catalog.
 *
 * ## A fixed query battery, not a query per table
 *
 * Six statements, whatever the schema holds. The alternative — walk the tables, then ask about each
 * one's columns — turns a 400-table database into 1,600 round trips, and the reader whose whole
 * promise is not to burden a production instance would be the heaviest thing on it.
 *
 * ## What it never does
 *
 * SELECTs against catalog relations, and nothing else: no user table is read, no lock is taken,
 * nothing is written. The session it runs through proves that about itself before the first of these
 * queries is issued ({@see ReaderSession}).
 */
final readonly class PgsqlCatalogReader implements CatalogReader
{
    /**
     * The relation kinds this version maps, and to what.
     *
     * `f` (foreign table) is deliberately absent — see {@see FOREIGN_TABLE_SKIP_REASON}.
     *
     * @var array<string, SchemaObjectType>
     */
    private const array RELATION_KINDS = [
        'r' => SchemaObjectType::Table,
        'p' => SchemaObjectType::Table,
        'v' => SchemaObjectType::View,
        'm' => SchemaObjectType::MaterializedView,
        'S' => SchemaObjectType::Sequence,
    ];

    /**
     * Why a foreign table is skipped rather than mapped.
     *
     * A decision, not an oversight: v1 has no rule that reasons about a foreign table, and mapping
     * one would mean carrying a `postgres_fdw` setup through every fixture for a branch nothing
     * reads. It is a NAMED skip so a schema that has one is told about it, rather than quietly
     * returning a snapshot that is short one object.
     */
    private const string FOREIGN_TABLE_SKIP_REASON = 'foreign table not read in v1';

    /**
     * PostgreSQL's own bookkeeping, never part of a reading.
     *
     * `pg_toast` and `pg_temp_*` hold storage the server manages for the user's tables; auditing
     * them would report findings about objects the project never wrote and cannot change.
     */
    private const array SYSTEM_SCHEMAS = ['pg_catalog', 'information_schema', 'pg_toast'];

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
        private CatalogCanonicalizer $canonicalizer = new CatalogCanonicalizer(IdentifierFolding::Lower),
        private CatalogPrivileges $privileges = new PgsqlCatalogPrivileges,
    ) {
        $this->subjectContext = $subjectContext->withConnection($session->instance());
    }

    /**
     * The object types this reader constructs — asserted here so a caller can read the scope.
     *
     * Ordered as the catalog is walked rather than alphabetically, because that is the order a reader
     * of {@see read()} meets them and a list that agrees with the code is one less thing to check.
     *
     * `pg_trigger` and `pg_proc` are BOTH read — the routine bodies and the trigger bindings drift
     * compares — and the security reader reads `pg_proc` a second time for a different question.
     *
     * ⚠️ This paragraph said "`pg_proc` and `pg_trigger` … neither is read here" until 2026-08-20,
     * eleven lines above the `SchemaObjectType::Routine` that had joined the list below it. It is
     * corrected rather than deleted because the correction is the point: a docblock that contradicts
     * the code it introduces is worse than none, and this one shipped. `ReaderScopeDeclarationTest`
     * holds the LIST against the reader's source and cannot read prose — which is exactly why the
     * prose drifted while every arm stayed green.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function readableObjectTypes(): array
    {
        return [
            SchemaObjectType::Table,
            SchemaObjectType::View,
            SchemaObjectType::MaterializedView,
            SchemaObjectType::Column,
            SchemaObjectType::Index,
            SchemaObjectType::Constraint,
            SchemaObjectType::Sequence,
            SchemaObjectType::Type,
            SchemaObjectType::Collation,
            SchemaObjectType::Routine,
            SchemaObjectType::Trigger,
        ];
    }

    public function read(CatalogRequest $request): CatalogSnapshot
    {
        $startedAt = hrtime(true);

        return $this->session->read(function (Connection $reader) use ($request, $startedAt): CatalogSnapshot {
            $schemas = new SchemaScope($request->schemas, self::SYSTEM_SCHEMAS)
                ->apply($this->defaultSchemas($reader), $this->existingSchemas($reader));

            $context = CatalogContext::of(
                'pgsql',
                $this->rawServerVersion($reader),
                $this->resolvedServerVersion($reader),
                $schemas,
                $request->tablePrefix,
            );

            $extensions = new ExtensionOwnershipFilter($request->includeExtensionObjects, $request->allowedExtensions);

            $objects = [];
            // Asked BEFORE the reading, not inferred from it afterwards: on a managed instance the
            // reading can succeed and still be a statement about nothing, and by then an empty
            // result is indistinguishable from a clean schema.
            $skips = new PrivilegeProbe($this->privileges)->run($reader, $schemas);
            /** @var array<string, true> $excludedRelations */
            $excludedRelations = [];

            foreach ($this->relations($reader, $schemas) as $row) {
                $kind = $this->str($row, 'relkind');
                $qualified = $this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'name'));

                if ($kind === 'f') {
                    $skips[] = CatalogSkip::for(
                        SchemaObjectType::Table,
                        $qualified,
                        SkipReason::UnsupportedDriver,
                        self::FOREIGN_TABLE_SKIP_REASON,
                    );

                    continue;
                }

                // No "unmapped kind" arm here, because the query cannot return one: its relkind
                // filter is DERIVED from this very map (plus the foreign table above). A defensive
                // branch would have been an arm nothing can fire — and an arm that never fires reads
                // as covered while proving nothing.
                $type = self::RELATION_KINDS[$kind];

                if (! $request->wants($type)) {
                    continue;
                }

                $owner = $this->str($row, 'owning_extension');

                if (! $extensions->includes($owner)) {
                    // Named, not dropped. "Why does the audit not mention my spatial tables?"
                    // deserves an answer, and a count of what was excluded is the difference
                    // between a scope decision and a silent absence.
                    $skips[] = CatalogSkip::for($type, $qualified, SkipReason::ExcludedByConfig, $extensions->reasonFor($owner), $owner);
                    $excludedRelations[$qualified] = true;

                    continue;
                }

                $objects[] = new SchemaObject(
                    $type,
                    $qualified,
                    $this->canonicalizer->name($this->str($row, 'schema')),
                    [
                        'relkind' => $kind,
                        'partitioned' => $kind === 'p',
                        'persistence' => $this->str($row, 'persistence'),
                        'comment' => $this->nullableStr($row, 'comment'),
                    ],
                    $this->subjectContext,
                    fromExtension: $owner !== '',
                    isPartition: $this->bool($row, 'is_partition'),
                );
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
                    static fn (): array => $query($reader, $schemas),
                    $type,
                    $type->value.'s',
                    $skips,
                );

                foreach ($read as $object) {
                    // A column of an excluded table is excluded WITH it, and silently: the one skip
                    // on the table already answers "why is spatial_ref_sys not in here?", while a
                    // skip per column would bury that answer under PostGIS's several hundred.
                    if (isset($excludedRelations[$object->parent ?? ''])) {
                        continue;
                    }

                    $objects[] = $object;
                }
            }

            if ($request->wants(SchemaObjectType::Type)) {
                foreach ($this->types($reader, $schemas, $extensions, $skips) as $object) {
                    $objects[] = $object;
                }
            }

            if ($request->wants(SchemaObjectType::Collation)) {
                foreach ($this->collations($reader) as $object) {
                    $objects[] = $object;
                }
            }

            if ($request->wants(SchemaObjectType::Routine)) {
                foreach ($this->routines($reader, $schemas, $extensions, $skips) as $object) {
                    $objects[] = $object;
                }
            }

            if ($request->wants(SchemaObjectType::Trigger)) {
                foreach ($this->triggers($reader, $schemas) as $object) {
                    $objects[] = $object;
                }
            }

            // Folded LAST, on the finished object list: the fold needs to see a partition's own
            // indexes to spot a divergent one, and those only exist once every query has run.
            if (! $request->reportPartitionsIndividually) {
                $objects = new PartitionResolver($this->partitionParents($reader, $schemas))->fold($objects);
            }

            // After the fold, because a partition's own object is gone by then: applying the prefix
            // first would name each partition in a skip for a table the fold was about to absorb.
            $objects = new TablePrefix($request->tablePrefix, $request->prefixScope)->applyTo($objects, $skips);

            // Last, on what the reading actually reports: an index excluded by the prefix scope or
            // absorbed by the fold must not leave an undetermined behind for an object nobody will
            // see in the snapshot.
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
     * Every partition mapped to its ROOT parent, resolved recursively.
     *
     * The recursion is the point: a sub-partition's immediate parent is another partition, and a
     * user thinks in terms of the table they created. Folding onto the intermediate level would
     * produce a snapshot whose objects nobody wrote and nobody recognizes.
     *
     * @param  list<string>  $schemas
     * @return array<string, string>
     */
    private function partitionParents(Connection $reader, array $schemas): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            WITH RECURSIVE tree AS (
                SELECT i.inhrelid AS child, i.inhparent AS parent
                FROM pg_inherits i
                UNION ALL
                SELECT t.child, i.inhparent
                FROM tree t
                JOIN pg_inherits i ON i.inhrelid = t.parent
            ),
            roots AS (
                SELECT DISTINCT ON (child) child, parent
                FROM tree
                WHERE parent NOT IN (SELECT inhrelid FROM pg_inherits)
            )
            SELECT cn.nspname AS child_schema, cc.relname AS child_name,
                   pn.nspname AS parent_schema, pc.relname AS parent_name
            FROM roots r
            JOIN pg_class cc ON cc.oid = r.child
            JOIN pg_namespace cn ON cn.oid = cc.relnamespace
            JOIN pg_class pc ON pc.oid = r.parent
            JOIN pg_namespace pn ON pn.oid = pc.relnamespace
            WHERE cc.relispartition
              AND cn.nspname = ANY (?)
            SQL, [$this->arrayLiteral($schemas)]);

        $parents = [];

        foreach ($rows as $row) {
            $child = $this->canonicalizer->qualified($this->str($row, 'child_schema'), $this->str($row, 'child_name'));
            $parents[$child] = $this->canonicalizer->qualified($this->str($row, 'parent_schema'), $this->str($row, 'parent_name'));
        }

        return $parents;
    }

    /**
     * The schemas a reading covers when the request names none: the session's REAL `search_path`,
     * resolved rather than assumed to be `public`.
     *
     * That assumption is the one that makes an audit quietly miss a project's own tables — a
     * multi-tenant or module-per-schema application keeps almost nothing in `public`.
     *
     * @return list<string>
     */
    private function defaultSchemas(Connection $reader): array
    {
        $rows = $this->rows(
            $reader,
            'SELECT nspname FROM pg_namespace WHERE nspname = ANY (current_schemas(false)) ORDER BY nspname',
            [],
        );

        return array_map(fn (array $row): string => $this->str($row, 'nspname'), $rows);
    }

    /**
     * Every schema this database actually has — the list a typo is checked against.
     *
     * Read from `pg_namespace` rather than `information_schema.schemata`, which shows only the
     * schemas the current role can access: a scope check built on it would report a schema that
     * exists as "does not exist" the moment the reader runs under a least-privileged role, which is
     * exactly the role it is meant to run under.
     *
     * @return list<string>
     */
    private function existingSchemas(Connection $reader): array
    {
        return array_map(
            fn (array $row): string => $this->str($row, 'nspname'),
            $this->rows($reader, 'SELECT nspname FROM pg_namespace ORDER BY nspname', []),
        );
    }

    /** The server's banner, verbatim — the build a report has to be able to name. */
    private function rawServerVersion(Connection $reader): string
    {
        return $this->str($this->rows($reader, 'SHOW server_version', [])[0] ?? [], 'server_version');
    }

    /**
     * The version a rule branches on, read from THIS session.
     *
     * `server_version_num` rather than the banner: it is the integer PostgreSQL itself compares on,
     * so a build suffix (`18.2 (Debian 18.2-1.pgdg120+1)`) cannot turn into a parse failure.
     */
    private function resolvedServerVersion(Connection $reader): ResolvedServerVersion
    {
        $row = $this->rows($reader, "SELECT current_setting('server_version_num') AS v", [])[0] ?? [];
        $num = (int) $this->str($row, 'v');

        return ResolvedServerVersion::detected(ServerVersion::of(intdiv($num, 10000), $num % 10000, 0, 'pgsql'));
    }

    /**
     * Every relation in scope, with the two facts a later ticket needs and this one only carries:
     * whether an extension owns it, and whether it is a partition of something.
     *
     * @param  list<string>  $schemas
     * @return list<array<string, scalar|null>>
     */
    private function relations(Connection $reader, array $schemas): array
    {
        return $this->rows($reader, <<<SQL
            SELECT n.nspname            AS schema,
                   c.relname            AS name,
                   c.relkind            AS relkind,
                   c.relpersistence     AS persistence,
                   c.relispartition     AS is_partition,
                   -- The table's comment, and NULL when it has none. Nullable on purpose: a table
                   -- with an empty comment and a table with no comment are different states, and a
                   -- rule about missing documentation has to be able to tell them apart.
                   obj_description(c.oid, 'pg_class') AS comment,
                   COALESCE((
                       SELECT e.extname FROM pg_depend d
                       JOIN pg_extension e ON e.oid = d.refobjid
                       WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e'
                       LIMIT 1
                   ), '')              AS owning_extension
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY (?)
              -- Filtered here rather than after the fact, and the reason is not performance:
              -- pg_class also holds one relation per INDEX and one TOAST table per table with a
              -- large column. Without this, a perfectly readable schema produced dozens of
              -- "unmapped relation kind" skips and reported itself PARTIAL — found the first time
              -- the reader met a real database, which is what that test is for.
              AND c.relkind IN ({$this->readableRelkinds()})
            ORDER BY n.nspname, c.relname
            SQL, [$this->arrayLiteral($schemas)]);
    }

    /**
     * The relkinds the reader can actually turn into objects, as a quoted SQL list.
     *
     * Derived from the mapping rather than written out beside it. The two spellings drifting apart
     * is not hypothetical: a kind added to the SQL and not to the map would arrive with nothing to
     * become, and a kind added to the map and not to the SQL would be a mapping the query can never
     * reach. Derived, neither is expressible.
     */
    private function readableRelkinds(): string
    {
        // The foreign table is in the query and NOT in the map on purpose: it is read in order to be
        // skipped by name, which is the one case where "no mapping" is the answer rather than a gap.
        $kinds = [...array_keys(self::RELATION_KINDS), 'f'];

        return implode(', ', array_map(static fn (string $kind): string => "'".$kind."'", $kinds));
    }

    /**
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function columns(Connection $reader, array $schemas): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT n.nspname                                    AS schema,
                   c.relname                                    AS relation,
                   a.attname                                    AS name,
                   format_type(a.atttypid, a.atttypmod)         AS raw_type,
                   a.attnotnull                                 AS not_null,
                   pg_get_expr(d.adbin, d.adrelid)              AS default_expression,
                   a.attidentity                                AS identity,
                   a.attgenerated                               AS generated,
                   co.collname                                  AS collation,
                   -- Read separately from the table's, because they answer different questions and a
                   -- project may require one without the other.
                   col_description(a.attrelid, a.attnum)        AS comment,
                   -- The half of `serial` that no type name reveals. `serial` is a MACRO, not a
                   -- type: it expands to a column, a sequence, a default, and an AUTO dependency
                   -- tying the sequence's lifetime to the column's. `format_type` reports `bigint`
                   -- either way, so the dependency is the only place the construction is written
                   -- down. Matched on `refobjsubid` — the COLUMN, not the table — because a
                   -- sequence owned by a sibling column while this one merely defaults from it is
                   -- an ordinary shared-sequence schema, and a table-level match would call it
                   -- serial. `deptype = 'a'` is what separates it from an identity column, whose
                   -- sequence hangs off the same column as an INTERNAL ('i') dependency.
                   (SELECT s.relname
                      FROM pg_depend dep
                      JOIN pg_class s ON s.oid = dep.objid AND s.relkind = 'S'
                     WHERE dep.classid = 'pg_class'::regclass
                       AND dep.refclassid = 'pg_class'::regclass
                       AND dep.refobjid = a.attrelid
                       AND dep.refobjsubid = a.attnum
                       AND dep.deptype = 'a'
                     LIMIT 1)                                   AS owned_sequence
            FROM pg_attribute a
            JOIN pg_class c ON c.oid = a.attrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
            LEFT JOIN pg_collation co ON co.oid = a.attcollation AND co.collname <> 'default'
            WHERE n.nspname = ANY (?)
              AND a.attnum > 0
              AND NOT a.attisdropped
              AND c.relkind IN ('r', 'p', 'v', 'm')
            ORDER BY n.nspname, c.relname, a.attnum
            SQL, [$this->arrayLiteral($schemas)]);

        return array_map(function (array $row): SchemaObject {
            $relation = $this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'relation'));
            $type = $this->canonicalizer->type($this->str($row, 'raw_type'));

            return new SchemaObject(
                SchemaObjectType::Column,
                $relation.'.'.$this->canonicalizer->name($this->str($row, 'name')),
                $relation,
                [
                    'type' => $type->name,
                    'raw_type' => $type->raw,
                    'not_null' => $this->bool($row, 'not_null'),
                    'default' => $this->canonicalizer->defaultExpression($this->nullableStr($row, 'default_expression')),
                    // `a` is ALWAYS, `d` is BY DEFAULT, '' is neither — the distinction a rule about
                    // identity columns needs, and one `information_schema` flattens.
                    'identity' => $this->str($row, 'identity'),
                    'generated' => $this->str($row, 'generated'),
                    'collation' => $this->canonicalizer->collation($this->nullableStr($row, 'collation')),
                    'comment' => $this->nullableStr($row, 'comment'),
                    // Null means the catalog says no sequence is tied to this column's lifetime —
                    // a fact, not an absence of one. `pg_depend` is readable without any privilege
                    // on the table (measured on 18.4 with a role holding only USAGE on the schema),
                    // so a column read that succeeded read this too.
                    'owned_sequence' => $this->ownedSequence($row),
                ],
                $this->subjectContext,
            );
        }, $rows);
    }

    /**
     * The sequence whose lifetime this column owns, canonicalized — or null when there is none.
     *
     * @param  array<string, scalar|null>  $row
     */
    private function ownedSequence(array $row): ?string
    {
        $sequence = $this->nullableStr($row, 'owned_sequence');

        return $sequence === null || $sequence === ''
            ? null
            : $this->canonicalizer->name($sequence);
    }

    /**
     * A server-computed day count, or null when the server had nothing to compute it from.
     *
     * Narrowed rather than cast: a non-numeric value here would mean the query returned something
     * this reader does not understand, and turning that into `0` would say "the window is brand
     * new" — the one answer that makes a rule report nothing while looking like it checked.
     */
    private function wholeDays(mixed $value): ?int
    {
        return is_numeric($value) ? (int) $value : null;
    }

    /**
     * How often each index has been read, and since when the server has been counting.
     *
     * Two facts from two views, and the second one decides whether the first means anything.
     * `pg_stat_user_indexes.idx_scan` is a counter; `pg_stat_database.stats_reset` says when it
     * started. Measured on 18.4: on a cluster nobody has reset, `stats_reset` comes back NULL — the
     * ordinary state, and the one where a zero count says nothing at all.
     *
     * Read through the session like every other query here, so it inherits the same timeouts and
     * the same read-only promise. A failure is a NAMED unavailability rather than an exception: a
     * managed instance that hides the statistics views must not make the whole audit fall over, and
     * must not look like a database whose indexes are all unused either.
     */
    public function indexUsage(CatalogRequest $request): IndexUsageReading
    {
        return $this->session->read(function (Connection $reader) use ($request): IndexUsageReading {
            try {
                // The SCOPE resolution is inside the try as well, and that placement was a defect
                // until a test caught it: those two queries read the catalog too, and a failure
                // there escaped the accessor and took the whole audit down — over a set of counters
                // that were never essential to it.
                $schemas = new SchemaScope($request->schemas, self::SYSTEM_SCHEMAS)
                    ->apply($this->defaultSchemas($reader), $this->existingSchemas($reader));

                $rows = $this->rows($reader, <<<'SQL'
                    SELECT schemaname AS schema, indexrelname AS name, idx_scan AS scans
                    FROM pg_stat_user_indexes
                    WHERE schemaname = ANY (?)
                    ORDER BY schemaname, indexrelname
                    SQL, [$this->arrayLiteral($schemas)]);

                // The window's age is computed by the SERVER, in the same statement that reads its
                // start. A second clock in PHP could disagree with the one that stamped the reset
                // by more than the threshold a rule compares against — and whole DAYS rather than
                // an instant so two audits on one day still produce byte-identical output.
                $reset = $this->rows($reader, <<<'SQL'
                    SELECT stats_reset::text AS reset_at,
                           CASE WHEN stats_reset IS NULL THEN NULL
                                ELSE FLOOR(EXTRACT(EPOCH FROM (now() - stats_reset)) / 86400)::int
                           END AS window_days
                    FROM pg_stat_database WHERE datname = current_database()
                    SQL, []);
            } catch (Throwable) {
                // Named, never swallowed as an empty reading. A role that cannot see the statistics
                // views and a database whose indexes are genuinely unused produce the same empty
                // list, and only one of them is a finding.
                return IndexUsageReading::unavailable();
            }

            $scans = [];

            foreach ($rows as $row) {
                $scans[$this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'name'))]
                    = (int) ($row['scans'] ?? 0);
            }

            $resetAt = $this->nullableStr($reset[0] ?? [], 'reset_at');

            return new IndexUsageReading(
                $scans,
                $resetAt === '' ? null : $resetAt,
                $this->wholeDays($reset[0]['window_days'] ?? null),
            );
        });
    }

    /**
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function indexes(Connection $reader, array $schemas): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT n.nspname                              AS schema,
                   t.relname                              AS relation,
                   i.relname                              AS name,
                   am.amname                              AS method,
                   x.indisunique                          AS is_unique,
                   x.indisprimary                         AS is_primary,
                   x.indisvalid                           AS is_valid,
                   -- Whether this unique index counts two NULLs as the same value. Measured on
                   -- 18.4, and it is the difference between a constraint that holds and one that
                   -- does not: under the default (NULLS DISTINCT) three rows sharing every other
                   -- column, each with a NULL in one member, all coexist under a UNIQUE index. A
                   -- rule that could not read this flag would either stay silent about that, or
                   -- report the schema that already applied NULLS NOT DISTINCT — punishing exactly
                   -- the author who fixed it.
                   x.indnullsnotdistinct                  AS nulls_not_distinct,
                   -- Whether the index carries an INCLUDE payload. Measured, and it decides a
                   -- redundancy verdict outright: `(a) INCLUDE (b)` and `(a)` report the SAME key
                   -- columns, because indnkeyatts deliberately excludes the payload. Without this
                   -- flag a redundancy rule would tell somebody to drop the index that carries the
                   -- payload, in favor of the one that does not.
                   (x.indnatts > x.indnkeyatts)           AS has_include,
                   pg_get_expr(x.indpred, x.indrelid)     AS predicate,
                   -- An expression index indexes lower(email), not email. Read as the expression
                   -- itself rather than as a flag: a reader told only "this is an expression" can
                   -- say nothing useful about it, and the text is what a finding has to quote.
                   pg_get_expr(x.indexprs, x.indrelid)     AS expression,
                   -- Only the NON-default classes. text_pattern_ops serves LIKE 'foo%' and the
                   -- default class does not, so two indexes on one column with different classes
                   -- are two different indexes. Measured: a GIN index over an array reports none,
                   -- because array_ops IS gin's default — the signal stays orthogonal to the method.
                   (SELECT string_agg(o.opcname, ', ' ORDER BY o.opcname)
                      FROM unnest(x.indclass::oid[]) c
                      JOIN pg_opclass o ON o.oid = c
                     WHERE NOT o.opcdefault)             AS operator_classes,
                   -- The KEY columns, in order, without the INCLUDE payload — measured:
                   -- indnkeyatts excludes it while indnatts does not, and an INCLUDE column
                   -- covers no lookup, so counting it would make a foreign key look indexed
                   -- when it is not. pg_get_indexdef() per position yields the expression for
                   -- an expression index, which is why it is used instead of reading attnames.
                   (SELECT string_agg(pg_get_indexdef(x.indexrelid, n, true), ', ' ORDER BY n)
                      FROM generate_series(1, x.indnkeyatts) AS n) AS key_columns,
                   pg_get_indexdef(x.indexrelid)          AS definition
            FROM pg_index x
            JOIN pg_class i ON i.oid = x.indexrelid
            JOIN pg_class t ON t.oid = x.indrelid
            JOIN pg_namespace n ON n.oid = t.relnamespace
            JOIN pg_am am ON am.oid = i.relam
            WHERE n.nspname = ANY (?)
            ORDER BY n.nspname, t.relname, i.relname
            SQL, [$this->arrayLiteral($schemas)]);

        return array_map(function (array $row): SchemaObject {
            $relation = $this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'relation'));

            return new SchemaObject(
                SchemaObjectType::Index,
                $this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'name')),
                $relation,
                [
                    'method' => $this->str($row, 'method'),
                    'unique' => $this->bool($row, 'is_unique'),
                    'primary' => $this->bool($row, 'is_primary'),
                    // The corpse a canceled CREATE INDEX CONCURRENTLY leaves: present, named, and
                    // used by nothing. It is carried here because the deploy suite's after-care is
                    // built on it — and because `information_schema` cannot express it at all.
                    'valid' => $this->bool($row, 'is_valid'),
                    // Read for EVERY index, not only the unique ones. A flag that appears on some
                    // objects and not others cannot be relied on to be there when it matters, and
                    // a rule would have to know which absence means what.
                    'nulls_not_distinct' => $this->bool($row, 'nulls_not_distinct'),
                    'has_include' => $this->bool($row, 'has_include'),
                    'key_columns' => $this->str($row, 'key_columns'),
                    'predicate' => $this->nullableStr($row, 'predicate'),
                    'expression' => $this->nullableStr($row, 'expression'),
                    'operator_classes' => $this->nullableStr($row, 'operator_classes'),
                    'definition' => $this->str($row, 'definition'),
                ],
                $this->subjectContext,
            );
        }, $rows);
    }

    /**
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function constraints(Connection $reader, array $schemas): array
    {
        $rows = $this->rows($reader, <<<'SQL_WRAP'
        SELECT n.nspname                        AS schema,
               t.relname                        AS relation,
               k.conname                        AS name,
               k.contype                        AS contype,
               k.convalidated                   AS validated,
               k.confupdtype                    AS on_update,
               k.confdeltype                    AS on_delete,
               -- The constraint's own columns, in the order it declares them. A foreign
               -- key is covered only by an index whose LEFT PREFIX is this list, so the
               -- order is the fact and not a detail.
               (SELECT string_agg(a.attname, ', ' ORDER BY c.ord)
                  FROM unnest(k.conkey) WITH ORDINALITY AS c(attnum, ord)
                  JOIN pg_attribute a ON a.attrelid = k.conrelid AND a.attnum = c.attnum)
                                                AS key_columns,
               -- The far end of a foreign key, which PostgreSQL records and this reader did
               -- not. Without it every cross-table question about a key -- do the two sides
               -- share a type, a collation, an encoding -- is unaskable on this engine, and
               -- `TableMembers` said so in its own docblock: "the PostgreSQL reader records no
               -- referenced table on a constraint, so no edge is described there".
               --
               -- NULL for every constraint that is not a foreign key, which is the honest shape:
               -- a check constraint references nothing, and an empty string would read as a
               -- reference that could not be resolved.
               CASE WHEN k.contype = 'f'
                    THEN (SELECT rn.nspname || '.' || rt.relname
                            FROM pg_class rt
                            JOIN pg_namespace rn ON rn.oid = rt.relnamespace
                           WHERE rt.oid = k.confrelid)
               END                              AS referenced_table,
               -- Ordered by POSITION, not by name: a composite key pairs its own column 0 with
               -- the referenced column 0, and a name-ordered list would pair the wrong ends the
               -- moment the two tables spell their columns differently.
               CASE WHEN k.contype = 'f'
                    THEN (SELECT string_agg(ra.attname, ', ' ORDER BY rc.ord)
                            FROM unnest(k.confkey) WITH ORDINALITY AS rc(attnum, ord)
                            JOIN pg_attribute ra ON ra.attrelid = k.confrelid AND ra.attnum = rc.attnum)
               END                              AS referenced_columns,
               pg_get_constraintdef(k.oid)      AS definition
        FROM pg_constraint k
        JOIN pg_class t ON t.oid = k.conrelid
        JOIN pg_namespace n ON n.oid = t.relnamespace
        WHERE n.nspname = ANY (?)
        ORDER BY n.nspname, t.relname, k.conname
        SQL_WRAP, [$this->arrayLiteral($schemas)]);

        return array_map(function (array $row): SchemaObject {
            $relation = $this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'relation'));

            return new SchemaObject(
                SchemaObjectType::Constraint,
                $this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'name')),
                $relation,
                [
                    // f = foreign key, c = check, p = primary key, u = unique, x = exclusion.
                    'contype' => $this->str($row, 'contype'),
                    'key_columns' => $this->str($row, 'key_columns'),
                    // NOT VALID: the constraint exists and the existing rows were never checked
                    // against it. A fact `information_schema` does not carry, and the whole point of
                    // the ADD CONSTRAINT … NOT VALID pattern this package recommends.
                    'validated' => $this->bool($row, 'validated'),
                    // Normalized to the SQL words both engines' rules read. pg_constraint
                    // stores a single letter; MySQL stores the words. A rule that had to know which
                    // is exactly the coupling this layer removes.
                    'on_update' => ReferentialAction::read($this->str($row, 'on_update'))->value,
                    'on_delete' => ReferentialAction::read($this->str($row, 'on_delete'))->value,
                    // Both nullable, and read as such: a non-foreign-key constraint references
                    // nothing, and `null` is the answer to "what does it point at" rather than an
                    // empty reference. `TableMembers` distinguishes the two, and a rule reading an
                    // empty string as a resolved edge would compare a column against nothing.
                    'referenced_relation' => $this->referencedRelation($row),
                    'referenced_columns' => $this->nullableStr($row, 'referenced_columns'),
                    'definition' => $this->str($row, 'definition'),
                ],
                $this->subjectContext,
            );
        }, $rows);
    }

    /**
     * The referenced table of a foreign key, spelled the way every other name in this reader is.
     *
     * The query returns `schema.table` already joined, because `confrelid::regclass` would spell it
     * according to the SESSION's `search_path` — a name that changes with the connection is exactly
     * what the canonicalization layer exists to prevent. Split and re-qualified here so it goes
     * through the same canonicalizer as the constraint's own name, rather than being trusted as a
     * string the server happened to build.
     *
     * @param  array<string, bool|float|int|string|null>  $row
     */
    private function referencedRelation(array $row): ?string
    {
        $raw = $this->nullableStr($row, 'referenced_table');

        if ($raw === null || $raw === '') {
            return null;
        }

        $parts = explode('.', $raw, 2);

        return count($parts) === 2
            ? $this->canonicalizer->qualified($parts[0], $parts[1])
            : $raw;
    }

    /**
     * User-defined types: domains and enums.
     *
     * Enums matter here more than they look: adding a value to one is the irreversible change a
     * level-4 rule reports, and the audit side needs to see which enums a database actually has.
     *
     * @param  list<string>  $schemas
     * @param  list<CatalogSkip>  $skips  appended to for every type an extension owns
     * @return list<SchemaObject>
     */
    private function types(Connection $reader, array $schemas, ExtensionOwnershipFilter $extensions, array &$skips): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT n.nspname     AS schema,
                   t.typname     AS name,
                   t.typtype     AS typtype,
                   COALESCE((
                       SELECT e.extname FROM pg_depend d
                       JOIN pg_extension e ON e.oid = d.refobjid
                       WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e'
                       LIMIT 1
                   ), '')        AS owning_extension
            FROM pg_type t
            JOIN pg_namespace n ON n.oid = t.typnamespace
            WHERE n.nspname = ANY (?)
              AND t.typtype IN ('d', 'e')
            ORDER BY n.nspname, t.typname
            SQL, [$this->arrayLiteral($schemas)]);

        $types = [];

        foreach ($rows as $row) {
            $owner = $this->str($row, 'owning_extension');
            $qualified = $this->canonicalizer->qualified($this->str($row, 'schema'), $this->str($row, 'name'));

            if (! $extensions->includes($owner)) {
                $skips[] = CatalogSkip::for(SchemaObjectType::Type, $qualified, SkipReason::ExcludedByConfig, $extensions->reasonFor($owner), $owner);

                continue;
            }

            $types[] = new SchemaObject(
                SchemaObjectType::Type,
                $qualified,
                $this->canonicalizer->name($this->str($row, 'schema')),
                ['typtype' => $this->str($row, 'typtype')],
                $this->subjectContext,
                fromExtension: $owner !== '',
            );
        }

        return $types;
    }

    /**
     * The triggers on tables in scope, keyed by the table they hang on.
     *
     * ## The identity is the PAIR, and that is not a detail
     *
     * A trigger name is unique per table, not per schema. `pg_trigger` will happily hold two rows
     * named `audit_row` on two different tables, and they are two objects. Keying on the name alone
     * folds them into one whose attributes appear to change with the reading order — the shape of
     * bug that produces drift on an unchanged database, which is the failure this suite exists to
     * not have.
     *
     * ## `tgisinternal` is excluded, and it is the whole noise story here
     *
     * PostgreSQL implements every foreign key as a PAIR of internal triggers on the referencing and
     * referenced tables. They are not user objects, nobody wrote them, and their names carry an OID
     * (`RI_ConstraintTrigger_c_16234`) that CHANGES when the constraint is recreated — so a replay
     * of the same migrations produces different names for the same constraints. Reading them would
     * report drift on every foreign key of an untouched schema. The constraint itself is already
     * compared as {@see SchemaObjectType::Constraint}, so nothing is lost by leaving them out.
     *
     * ## What drifts here is the BINDING, not a body
     *
     * A PostgreSQL trigger names a function; it has no inline body. The function's body is compared
     * separately as {@see SchemaObjectType::Routine}, so what this reading has to catch is the
     * binding — when it fires, on what, and which function it calls. `pg_get_triggerdef()` renders
     * exactly that, and it is a RECONSTRUCTION rather than stored text: the server normalizes the
     * spelling, so two servers given the same migration return the same string.
     *
     * It still goes through {@see CatalogCanonicalizer::routineBody()}, for line endings and
     * trailing whitespace, because that argument is made once and applies to any definition text.
     * Using the SHARED canonicalizer rather than a second one is deliberate: two text normalizers
     * that may disagree about where a body ends are the same defect in green.
     *
     * @param  list<string>  $schemas
     * @return list<SchemaObject>
     */
    private function triggers(Connection $reader, array $schemas): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT n.nspname                        AS schema,
                   c.relname                        AS table_name,
                   t.tgname                         AS name,
                   pg_get_triggerdef(t.oid)         AS definition,
                   t.tgenabled                      AS enabled
            FROM pg_trigger t
            JOIN pg_class c ON c.oid = t.tgrelid
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = ANY (?)
              AND NOT t.tgisinternal
            ORDER BY n.nspname, c.relname, t.tgname
            SQL, [$this->arrayLiteral($schemas)]);

        $triggers = [];

        foreach ($rows as $row) {
            $schema = $this->str($row, 'schema');
            $table = $this->str($row, 'table_name');

            // Table-qualified, so the two `audit_row` triggers above stay two objects. The table
            // travels in the IDENTITY rather than in the attributes for the same reason the routine
            // argument list does: moving a trigger to another table is not that trigger changing,
            // it is one object gone and another arrived.
            $qualified = $this->canonicalizer->qualified($schema, $table).'.'.$this->canonicalizer->name($this->str($row, 'name'));

            $triggers[] = new SchemaObject(
                SchemaObjectType::Trigger,
                $qualified,
                $this->canonicalizer->name($schema),
                [
                    'definition' => $this->canonicalizer->routineBody($this->str($row, 'definition')),
                    // Spelled out in the DRIVER, like the routine kind beside it: `O` means nothing
                    // to a reader of a report, and the core stays free of engine vocabulary.
                    'enabled' => match ($this->str($row, 'enabled')) {
                        'D' => 'disabled',
                        'R' => 'replica',
                        'A' => 'always',
                        default => 'origin',
                    },
                ],
                $this->subjectContext,
            );
        }

        return $triggers;
    }

    /**
     * Every function and procedure this project owns, with a body that compares.
     *
     * ## The identity carries the arguments, and it has to
     *
     * PostgreSQL allows overloading: `sqlens_fee(int)` and `sqlens_fee(numeric)` are two routines
     * with one name. Keyed on the name alone, one would shadow the other and a drift run would
     * report a difference between two objects that were never the same object.
     *
     * ## Only `f` and `p`
     *
     * `prokind` also carries `a` (aggregate) and `w` (window). Neither is something a Laravel
     * migration creates, and both arrive in bulk with extensions — they would be noise with a
     * plausible-looking name.
     *
     * ## The body goes through the SHARED canonicalizer
     *
     * `prosrc` is read rather than `pg_get_functiondef()`, and the reason is measured on PostgreSQL
     * 18.4 rather than assumed: the reconstruction normalizes the SIGNATURE and embeds the body byte
     * for byte, so it would buy the signature — which this reader already assembles from its own
     * columns — and nothing at all for the part that actually needs canonicalizing.
     *
     * What that canonicalization may and may not do is argued once, at
     * {@see CatalogCanonicalizer::routineBody()}, because MySQL faces the identical question and two
     * copies of that reasoning would drift apart.
     *
     * @param  list<string>  $schemas
     * @param  list<CatalogSkip>  $skips  appended to for every routine an extension owns
     * @return list<SchemaObject>
     */
    private function routines(Connection $reader, array $schemas, ExtensionOwnershipFilter $extensions, array &$skips): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT n.nspname                                  AS schema,
                   p.proname                                  AS name,
                   pg_get_function_identity_arguments(p.oid)  AS arguments,
                   p.prokind                                  AS kind,
                   l.lanname                                  AS language,
                   p.provolatile                              AS volatility,
                   p.prosecdef                                AS security_definer,
                   pg_get_function_result(p.oid)              AS result,
                   p.prosrc                                   AS body,
                   COALESCE((
                       SELECT e.extname FROM pg_depend d
                       JOIN pg_extension e ON e.oid = d.refobjid
                       WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
                       LIMIT 1
                   ), '')                                     AS owning_extension
            FROM pg_proc p
            JOIN pg_namespace n ON n.oid = p.pronamespace
            JOIN pg_language l ON l.oid = p.prolang
            WHERE n.nspname = ANY (?)
              AND p.prokind IN ('f', 'p')
            ORDER BY n.nspname, p.proname, 3
            SQL, [$this->arrayLiteral($schemas)]);

        $routines = [];

        foreach ($rows as $row) {
            $owner = $this->str($row, 'owning_extension');
            $arguments = $this->str($row, 'arguments');
            $schema = $this->str($row, 'schema');

            // The argument list belongs to the IDENTITY rather than to the attributes: two overloads
            // are two objects, and an attribute would make them one object that keeps changing.
            $qualified = $this->canonicalizer->qualified($schema, $this->str($row, 'name')).'('.$arguments.')';

            if (! $extensions->includes($owner)) {
                $skips[] = CatalogSkip::for(SchemaObjectType::Routine, $qualified, SkipReason::ExcludedByConfig, $extensions->reasonFor($owner), $owner);

                continue;
            }

            $routines[] = new SchemaObject(
                SchemaObjectType::Routine,
                $qualified,
                $this->canonicalizer->name($schema),
                [
                    // Spelled out in the DRIVER, like the collation provider beside it: the core
                    // stays free of engine vocabulary, and `f` means nothing to a reader of a report.
                    'routine_kind' => $this->str($row, 'kind') === 'p' ? 'procedure' : 'function',
                    'language' => $this->str($row, 'language'),
                    'volatility' => match ($this->str($row, 'volatility')) {
                        'i' => 'immutable',
                        's' => 'stable',
                        default => 'volatile',
                    },
                    'security_definer' => $this->bool($row, 'security_definer'),
                    'result' => $this->str($row, 'result'),
                    'body' => $this->canonicalizer->routineBody($this->str($row, 'body')),
                ],
                $this->subjectContext,
                fromExtension: $owner !== '',
            );
        }

        return $routines;
    }

    /**
     * The collations whose recorded version can be compared against the installed one.
     *
     * Two sources, one subject type. The DATABASE's own collation lives on `pg_database` and is the
     * one almost every index in an ordinary schema is actually built on; explicitly created
     * collations live on `pg_collation`. A rule asking "has this drifted" asks the same question of
     * both, so splitting them into two types would be the same rule twice.
     *
     * The two version functions are NOT interchangeable, and the difference is not cosmetic:
     * `pg_database_collation_actual_version()` takes a database oid and
     * `pg_collation_actual_version()` takes a collation oid. Measured on PostgreSQL 18, handing the
     * second a database oid answers `ERROR: collation with OID … does not exist` — and would answer
     * the WRONG collation's version silently if some collation happened to carry that oid. One
     * function per source, named at the source.
     *
     * @return list<SchemaObject>
     */
    private function collations(Connection $reader): array
    {
        $rows = $this->rows($reader, <<<'SQL'
            SELECT 'database'                                              AS scope,
                   d.datname                                               AS name,
                   ''                                                      AS schema,
                   d.datlocprovider                                        AS provider,
                   d.datcollate                                            AS locale,
                   COALESCE(d.datcollversion, '')                          AS recorded,
                   COALESCE(pg_database_collation_actual_version(d.oid), '') AS actual
            FROM pg_database d
            WHERE d.datname = current_database()
            UNION ALL
            SELECT 'object'                                                AS scope,
                   c.collname                                              AS name,
                   n.nspname                                               AS schema,
                   c.collprovider                                          AS provider,
                   c.collcollate                                           AS locale,
                   COALESCE(c.collversion, '')                             AS recorded,
                   COALESCE(pg_collation_actual_version(c.oid), '')        AS actual
            FROM pg_collation c
            JOIN pg_namespace n ON n.oid = c.collnamespace
            WHERE n.nspname <> ALL (?)
            ORDER BY 1, 3, 2
            SQL, [$this->arrayLiteral(self::SYSTEM_SCHEMAS)]);

        $collations = [];

        foreach ($rows as $row) {
            $scope = $this->str($row, 'scope');
            $schema = $this->str($row, 'schema');
            $name = $this->str($row, 'name');

            $collations[] = new SchemaObject(
                SchemaObjectType::Collation,
                $schema === '' ? $name : $this->canonicalizer->qualified($schema, $name),
                $schema === '' ? null : $this->canonicalizer->name($schema),
                [
                    'collation_scope' => $scope,
                    // Mapped from PostgreSQL's single-character code in the DRIVER, not the rule:
                    // the core stays free of engine vocabulary. Its own class rather than a match
                    // inlined here, because inlined it is testable only through whatever providers
                    // the developer's machine happens to have — and this one has exactly one.
                    'provider' => CollationProvider::forCode($this->str($row, 'provider')),
                    'locale' => $this->str($row, 'locale'),
                    // Empty string means the server reported none. Preserved as '' rather than
                    // folded to null so the rule can tell "no version" from "no such column".
                    'recorded_version' => $this->str($row, 'recorded'),
                    'actual_version' => $this->str($row, 'actual'),
                ],
                $this->subjectContext,
            );
        }

        return $collations;
    }

    /**
     * Run one catalog query and return its rows as typed arrays.
     *
     * The conversion is here rather than at each call site because `select()` is typed as returning
     * a plain array of `stdClass`, and reading a property off one is a hole a static analyzer
     * cannot see through. One place that narrows it means every mapper below reads values it can
     * prove the shape of.
     *
     * @param  list<string>  $bindings
     * @return list<array<string, scalar|null>>
     */
    #[RawSql(reason: 'pg_catalog SQL with a variable-length IN (...). The template is the package own constant text and the schema names travel as bindings')]
    private function rows(Connection $reader, string $sql, array $bindings): array
    {
        $rows = [];

        foreach ($reader->select($sql, $bindings) as $row) {
            $narrowed = [];

            foreach ((array) $row as $key => $value) {
                // A catalog column is a scalar or null. Anything else — a resource, an object from
                // a driver that returns one — is narrowed to null rather than cast, because a
                // stringified resource would be a value nobody can act on wearing the shape of one.
                $narrowed[(string) $key] = is_scalar($value) ? $value : null;
            }

            $rows[] = $narrowed;
        }

        return $rows;
    }

    /**
     * A required string column.
     *
     * @param  array<string, scalar|null>  $row
     */
    private function str(array $row, string $key): string
    {
        $value = $row[$key] ?? null;

        return is_scalar($value) ? (string) $value : '';
    }

    /**
     * An optional string column — null and the empty string are kept apart, because "no predicate"
     * and "an empty predicate" are different facts about an index.
     *
     * @param  array<string, scalar|null>  $row
     */
    private function nullableStr(array $row, string $key): ?string
    {
        $value = $row[$key] ?? null;

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * A boolean column. PostgreSQL hands `t`/`f` through some drivers and a real bool through
     * others, so both are read rather than one being assumed.
     *
     * @param  array<string, scalar|null>  $row
     */
    private function bool(array $row, string $key): bool
    {
        $value = $row[$key] ?? null;

        return in_array($value, [true, 't', 1, '1'], true);
    }

    /**
     * A PostgreSQL array literal for a schema list.
     *
     * Bound as ONE parameter rather than expanded into a placeholder per schema: the query text is
     * then the same whatever the scope is, which is what lets the server reuse a plan and what keeps
     * the query COUNT fixed. The names are catalog identifiers, and a quote inside one is doubled
     * rather than trusted.
     *
     * @param  list<string>  $schemas
     */
    private function arrayLiteral(array $schemas): string
    {
        return '{'.implode(',', array_map(
            static fn (string $schema): string => '"'.str_replace(['\\', '"'], ['\\\\', '\\"'], $schema).'"',
            $schemas,
        )).'}';
    }

    /** Whether a throwable was this reader's own budget firing rather than a fault in the catalog. */
    public function isOwnTimeout(Throwable $error): bool
    {
        return $this->session->isOwnTimeout($error);
    }
}
