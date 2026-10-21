<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * What a canonical statement does — the classification a rule matches on instead
 * of the raw SQL, so no rule ever has to regex the grammar output. Driver-agnostic:
 * the recognition that assigns a kind lives in the classifier stage and reads its
 * patterns from the driver; this enum is only the vocabulary.
 *
 * `Unknown` is a DELIBERATE outcome — a statement recognized as valid SQL but of no
 * kind we model, such as a `SELECT 1`. It is not the same as an undetermined
 * classification, which is a named CanonicalizationFailure meaning "could not be
 * decided". A convenient `DdlOther`/`Unknown` must never stand in for a real
 * undetermined — that is the "no silent green" line of this stage.
 *
 * On which side of that line a statement falls is measured, not assumed: a `SET`
 * has a kind of its own ({@see self::SessionSetting}), a PostgreSQL `COMMENT ON` is
 * {@see self::DdlOther}, an `ANALYZE` is `Unknown` on both engines, and so is a plain
 * `VACUUM`. A `VACUUM FULL`, a `CLUSTER` and MySQL's `OPTIMIZE TABLE` are
 * {@see self::RebuildTable}, and PostgreSQL's `REINDEX` and `REFRESH MATERIALIZED VIEW`
 * have kinds of their own. A `VACUUM` without FULL whose option list holds an option the
 * signatures do not read is not recognized, and that is deliberate: a statement read in part
 * is not read as harmless. It ends as a CanonicalizationFailure, which makes the whole
 * migration undetermined, and so does a `REINDEX DATABASE` or a MySQL `REPAIR TABLE`.
 *
 * The set is a superset of the plan's list: `DropTable` and `TruncateTable` are
 * carried as their own kinds (not folded into DdlOther) because the destructive
 * safety gate matches on them — a rule reaching for the raw text to find a DROP
 * TABLE would defeat the very guard this classification exists to enable.
 *
 * The backed values are output-facing, so they are stable lowercase.
 */
enum StatementKind: string
{
    case CreateTable = 'create_table';
    case AlterTable = 'alter_table';
    case DropTable = 'drop_table';
    /**
     * `DROP SCHEMA` — the one destructive statement that is not about a single object.
     *
     * It is captured on its own rather than falling into {@see self::DdlOther} because nothing reads
     * that case as a catch-all: exactly one rule looks at it, and it uses it to mean "the schema
     * changed", not "here is an unjudged statement". A schema drop therefore reached no rule at all,
     * while dropping one table inside that same schema reached two.
     *
     * Its SIBLINGS are deliberately absent, and the reason has been re-measured since it was first
     * written here. It used to say `ALTER SCHEMA` was "the ownership case … adding cases no rule
     * reads": that is now circular, because the ownership check does read a schema target — this
     * kind is what carries one to it.
     *
     * The standing reason is narrower and holds:
     *
     * - `CREATE SCHEMA` is not an ownership question at all. Nobody owns what does not exist yet;
     *   what a role needs there is `CREATE` on the DATABASE, which is a different check.
     * - `ALTER SCHEMA` has no Laravel builder API — it can only arrive as a raw statement, in one of
     *   two rare forms (`RENAME TO`, `OWNER TO`). The destructive sibling is the one that is
     *   captured, which is the right half to have if only one is: a `DROP SCHEMA` the role does not
     *   own fails the deploy and would have been irreversible had it succeeded.
     *
     * An `ALTER SCHEMA` therefore reaches the ownership check as an UNDERIVABLE requirement with its
     * reason named, never as silence.
     */
    case DropSchema = 'drop_schema';
    case TruncateTable = 'truncate_table';
    case CreateIndex = 'create_index';
    case CreateFulltextIndex = 'create_fulltext_index';
    case CreateSpatialIndex = 'create_spatial_index';
    case DropIndex = 'drop_index';
    case AddConstraint = 'add_constraint';
    case AddPrimaryKey = 'add_primary_key';
    case AddForeignKey = 'add_foreign_key';
    case DropConstraint = 'drop_constraint';
    case AddColumn = 'add_column';
    case AlterColumn = 'alter_column';
    case DropColumn = 'drop_column';
    case Rename = 'rename';
    /**
     * A maintenance statement that rewrites a whole table: PostgreSQL's `VACUUM FULL` and `CLUSTER`,
     * and MySQL's `OPTIMIZE TABLE`.
     *
     * None changes the schema, and each costs what a rebuild costs, which grows with the table and
     * not with the space it gives back. What the rebuild does to the table's availability is the
     * engine's own answer: `VACUUM FULL` and `CLUSTER` hold an ACCESS EXCLUSIVE lock until they are
     * done, and `OPTIMIZE TABLE` keeps an InnoDB table writable unless the table has a FULLTEXT
     * index, which makes it a copy. So the kind is shared and each engine's rules read it in their
     * own terms.
     *
     * It has its own case rather than sharing {@see self::DdlOther} or {@see self::Unknown}, because
     * a lead word cannot tell either statement from its harmless sibling: a plain `VACUUM` and an
     * `ANALYZE TABLE` are `Unknown`, and the signatures are what tell the rebuild apart.
     */
    case RebuildTable = 'rebuild_table';
    /**
     * PostgreSQL's `REINDEX INDEX` or `REINDEX TABLE`, which rebuilds an index that already exists.
     *
     * A kind of its own because its locks are neither a build's nor a rewrite's: without
     * CONCURRENTLY it holds SHARE on the table, so writes wait and reads go on, and ACCESS EXCLUSIVE
     * on each index it rebuilds, so a read that would use one waits. With CONCURRENTLY neither
     * blocks, and PostgreSQL refuses the statement inside a transaction block.
     */
    case Reindex = 'reindex';
    /**
     * PostgreSQL's `REFRESH MATERIALIZED VIEW`, which runs the view's query again and replaces what
     * the view holds.
     *
     * Without CONCURRENTLY it holds ACCESS EXCLUSIVE on the view for as long as the query runs, so
     * every read of the view waits; with it, an EXCLUSIVE lock that lets reads through. Unlike the
     * index forms, the concurrent refresh runs inside a transaction block.
     */
    case RefreshMaterializedView = 'refresh_materialized_view';
    /**
     * A session configuration command — `SET lock_timeout`, `SET LOCAL statement_timeout`,
     * `SET foreign_key_checks = 0`.
     *
     * Recognized valid SQL that changes no schema and writes no row. It has its own case rather
     * than sharing {@see self::Unknown} because the two mean opposite things to a rule that has to
     * reason about what it did not read: `Unknown` is "this statement was not recognized, so it
     * could be anything", and a rule facing it must hedge. A session setting is recognized, and
     * hedging over the `SET lock_timeout` preamble this package's own lock rules ASK a migration to
     * open with would put a hedge on every well-written migration.
     */
    case SessionSetting = 'session_setting';

    case Dml = 'dml';
    case DdlOther = 'ddl_other';
    case Unknown = 'unknown';
}
