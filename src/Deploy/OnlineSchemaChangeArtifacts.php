<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * The names an online-schema-change tool leaves behind on MySQL, and what each one was.
 *
 * ## These are not a suffix hunt, and the difference is the whole design
 *
 * The PostgreSQL sibling {@see TransitionObjectPatterns} matches shapes a PERSON writes when they
 * mean "temporary", and it says out loud that a name is not evidence. This list is narrower and
 * harder: every entry is a name a TOOL generates, to its own documented scheme, and no team writes
 * one by hand. `_users_gho` is gh-ost's ghost table. `#sql-1234_a` is what InnoDB calls the
 * temporary table an `ALGORITHM=COPY` rebuild works in — a name a user cannot even create without
 * quoting it.
 *
 * So the false-positive risk is genuinely lower here, and the check that uses this list is still
 * `undetermined` rather than `fail` for a different reason: a run in flight looks exactly like one
 * that died. gh-ost creates `_t_gho` and works in it for hours; catching it mid-migration and
 * calling it wreckage would report the healthy case as the broken one.
 *
 * ## The schemes, read from the tools' own documentation
 *
 * | pattern | tool | what it was |
 * |---|---|---|
 * | `_<table>_gho` | gh-ost | the ghost table the new schema is built in |
 * | `_<table>_ghc` | gh-ost | the changelog table it tracks its own progress in |
 * | `_<table>_del` | gh-ost | the original, renamed out of the way at cut-over |
 * | `_<table>_new` | pt-osc | the new table it copies into |
 * | `_<table>_old` | pt-osc | the original after the atomic rename |
 * | `#sql-…`, `#sql2-…`, `#sql-ib…` | InnoDB | the temporary table a COPY rebuild works in |
 *
 * The pt-osc TRIGGERS are named separately, because they are the half that keeps writing: an
 * `_t_new` table left behind costs storage, and a `pt_osc_db_t_ins` trigger left behind costs every
 * INSERT on the real table forever.
 */
final readonly class OnlineSchemaChangeArtifacts
{
    /**
     * Table names, as PCRE. Anchored at both ends where the scheme allows it.
     *
     * `_<table>_gho` is matched as "starts with an underscore and ends with `_gho`" rather than by
     * reconstructing the table name: a rebuild of `orders` produces `_orders_gho`, and a rebuild of
     * a table whose own name ends in `_gho` would otherwise be unmatchable. The leading underscore
     * is the discriminator that keeps `photo_gho`-shaped names out.
     *
     * @var list<string>
     */
    public const array TABLES = [
        '/^_.+_gho$/',
        '/^_.+_ghc$/',
        '/^_.+_del$/',
        '/^_.+_new$/',
        '/^_.+_old$/',
        // InnoDB's own temporary tables. The `#` makes them unquotable in ordinary SQL, which is why
        // no project creates one on purpose and why this pattern needs no further narrowing.
        '/^#sql/',
    ];

    /**
     * pt-online-schema-change's trigger names: `pt_osc_<db>_<table>_ins|upd|del`.
     *
     * @var list<string>
     */
    public const array TRIGGERS = [
        '/^pt_osc_.+_(ins|upd|del)$/',
    ];

    /** Whether this bare table name is one an online-schema-change tool generates. */
    public static function isTable(string $bareName): bool
    {
        return self::anyMatch(self::TABLES, $bareName);
    }

    /** Whether this trigger name is one pt-online-schema-change generates. */
    public static function isTrigger(string $bareName): bool
    {
        return self::anyMatch(self::TRIGGERS, $bareName);
    }

    /**
     * Which tool a name belongs to, for the message — the reader's next step depends on it.
     *
     * A gh-ost leftover means a `gh-ost` run to look at; a pt-osc trigger means a table that is
     * still paying for one. Reporting both as "an online-schema-change artifact" would make the
     * reader open the same investigation twice to find out which.
     */
    public static function toolFor(string $bareName): string
    {
        if (str_starts_with($bareName, '#sql')) {
            return 'InnoDB';
        }

        if (preg_match('/_(gho|ghc|del)$/', $bareName) === 1) {
            return 'gh-ost';
        }

        return 'pt-online-schema-change';
    }

    /** @param  list<string>  $patterns */
    private static function anyMatch(array $patterns, string $bareName): bool
    {
        return array_any($patterns, fn (string $pattern): bool => preg_match($pattern, $bareName) === 1);
    }
}
