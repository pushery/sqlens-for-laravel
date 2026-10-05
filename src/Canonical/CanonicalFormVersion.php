<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Contracts\DeclaresReservedWords;

/**
 * The canonical form is a versioned contract, not an implementation detail —
 * kin to the baseline / debt-ledger formats. The version travels with every
 * canonical statement so the later drift comparator can interpret
 * comparisons across time, and so an artifact produced by an unknown version is
 * a named undetermined case rather than a silently mis-read string.
 */
final readonly class CanonicalFormVersion
{
    /**
     * The version this build of the canonicalizer produces. Bumps on ANY change to the canonical
     * form — including one that only adds a keyword.
     *
     * The "only a keyword" exemption was considered and rejected, and the reason is what the
     * version is FOR. A consumer comparing two artifacts sees bytes, not causes: it cannot tell a
     * new normalization stage from a keyword list that grew, only that the same input now produces
     * a different string. A version that exempted the second kind would therefore mean "comparable"
     * while the artifacts are not — which is the single question it exists to answer.
     *
     * Bumping is cheap by construction: {@see self::isKnown()} accepts every version up to CURRENT,
     * so older artifacts stay readable. A number that moves often and means something is worth more
     * than one that stays at 1 and means nothing.
     *
     * Went to 2 for the three keyword extensions that had already changed the form without saying
     * so — once, not once per extension: the point is that the CURRENT form differs from form 1,
     * not how many commits it took to get there.
     *
     * Went to 3 for `SCHEMA`, added to the PostgreSQL list so `DROP SCHEMA` could match a signature
     * and reach a rule. It is the fourth keyword extension and the first to arrive with its bump
     * attached — the paragraph above describes the other three, which is a warning this one nearly
     * repeated. Measured before and after, and the drift is not theoretical:
     *
     *     alter table "users" add column schema varchar(255)
     *       form 2 -> ALTER TABLE users ADD COLUMN schema VARCHAR(255)
     *       form 3 -> ALTER TABLE users ADD COLUMN SCHEMA VARCHAR(255)
     *
     *     create table "schema" (id bigint)
     *       form 2 -> CREATE TABLE schema (id BIGINT)
     *       form 3 -> CREATE TABLE "schema" (id BIGINT)
     *
     * Both are more correct — an identifier colliding with a keyword keeps its quotes, which is
     * what makes it unambiguous — and both change the STRING, which is all a fingerprint compares.
     * A project with a column named `schema` would otherwise have seen its ledger report drift that
     * nothing in its own tree caused.
     *
     * Went to 4 for the GENERATED-column vocabulary — `ALWAYS`, `GENERATED`, `STORED` and `VIRTUAL`,
     * in BOTH driver lists. It is the fifth keyword extension and the second to arrive with its bump
     * attached rather than after the fact.
     *
     * Why these four were missing is the same reason the query vocabulary was: the keyword guard's
     * corpus is generated from the SCHEMA builder, and `GENERATED ALWAYS AS IDENTITY` is written by
     * hand or through `->change()`, never by the builder's ordinary path. So no corpus statement ever
     * carried them. Measured before and after:
     *
     *     create table t (id int generated always as identity, c int generated always as (b * 2) stored)
     *       form 3 -> CREATE TABLE t (id int generated always AS IDENTITY, c int generated always AS (b * 2) stored)
     *       form 4 -> CREATE TABLE t (id int GENERATED ALWAYS AS IDENTITY, c int GENERATED ALWAYS AS (b * 2) STORED)
     *
     * Only `AS` and `IDENTITY` folded before, so the same DDL in two casings produced two canonical
     * strings — two fingerprints for one statement, and a baseline entry that stopped matching the
     * moment somebody reformatted a migration. The words appear in no shipped rule pattern (measured,
     * with a control), so nothing was mis-reported; what moved was the fingerprint.
     *
     * Went to 5 for the bare words PostgreSQL folds. An unquoted name that was not a keyword was left
     * exactly as written, so one table had as many canonical forms as it had spellings, while the
     * server creates the same object from all of them. Measured before and after:
     *
     *     CREATE TABLE Orders (id integer)
     *       form 4 -> CREATE TABLE Orders (id INTEGER)
     *       form 5 -> CREATE TABLE orders (id INTEGER)
     *
     *     CREATE TABLE "orders" (id integer)
     *       form 4 -> CREATE TABLE orders (id INTEGER)
     *       form 5 -> CREATE TABLE orders (id INTEGER)
     *
     * The second did not move and the first now agrees with it. MySQL does not fold, because whether
     * `Orders` and `orders` are one table there depends on `lower_case_table_names`, and none of its
     * forms moved. The keyword lists did not change either, so the guard that pins them records form
     * 5 with the same lists as form 4.
     *
     * Form 5 also folds ASCII only, in a qualified name as much as in a bare one. Measured on
     * PostgreSQL 18.0 with a UTF-8 database, `create table Élan (Id int)` creates `Élan` with a
     * column `id`: the server downcases A to Z and nothing else. `mb_strtolower` had folded the `É`
     * too, so `Élan` and `"élan"`, two tables, shared a form. It went in before form 5 was
     * released, so it is part of 5 rather than a 6.
     *
     * Went to 6 for MySQL's backslash escape. Three stages each carried a scanner of their own for
     * quoted spans, and each knew only the doubled delimiter, so a literal Laravel writes through
     * `addslashes()` ended at its `\'` and the rest of the statement read as a literal that never
     * closes. Measured before and after, on what Laravel's MySQL grammar writes for a column comment
     * with an apostrophe:
     *
     *     create table `settings` (`key` varchar(255) not null comment 'the setting\'s key', `value` text not null, primary key (`key`))
     *       form 5 -> CREATE TABLE settings (`key` VARCHAR(255) NOT NULL comment 'the setting\'s KEY', `value` text not null, primary key (`key`))
     *       form 6 -> CREATE TABLE settings (`key` VARCHAR(255) NOT NULL comment 'the setting\'s key', value TEXT NOT NULL, PRIMARY KEY (`key`))
     *
     * PostgreSQL does not escape with a backslash, so none of its forms moved, and neither did the
     * keyword lists. The stages now share {@see QuotedSpan}, which asks the driver.
     *
     * Went to 7 for `CHECK`, added to the MySQL list so `DROP CHECK <k>` and an unnamed
     * `ADD CHECK (…)` match signatures of their own. Without it the word arrived as an identifier,
     * and the bare `DROP <c>` and `ADD <c>` read it as a column called `check`: a dropped column with
     * its data, reported for a migration that drops a constraint. Measured before and after:
     *
     *     alter table orders drop check orders_total_check
     *       form 6 -> ALTER TABLE orders DROP check orders_total_check
     *       form 7 -> ALTER TABLE orders DROP CHECK orders_total_check
     *
     *     alter table `orders` add `check` int
     *       form 6 -> ALTER TABLE orders ADD check INT
     *       form 7 -> ALTER TABLE orders ADD `check` INT
     *
     * The first is now a dropped constraint rather than a dropped column. The second keeps its quotes
     * because the name collides with a keyword, which is what tells it apart from the keyword. The
     * PostgreSQL list already carried the word, so none of its forms moved.
     *
     * Went to 8 for the words the server reserves. A name was quoted only when it collided with the
     * canonicalizer's own keyword list, and the server reserves more than that list holds: 62 of
     * PostgreSQL 18's 101 reserved words and 182 of MySQL 8.4's 262 were written bare, and every one
     * of them is a syntax error bare. The form reaches suggestions, so a remediation over a table
     * called `group` did not parse. A driver now declares its server's reserved set
     * ({@see DeclaresReservedWords}), and a name from it keeps its quotes.
     * The keyword lists did not change, so no keyword folds differently. Measured before and after:
     *
     *     create index "group_name_index" on "group" ("name")
     *       form 7 -> CREATE INDEX group_name_index ON group (name)
     *       form 8 -> CREATE INDEX group_name_index ON "group" (name)
     *
     *     alter table `players` add `rank` int not null
     *       form 7 -> ALTER TABLE players ADD rank INT NOT NULL
     *       form 8 -> ALTER TABLE players ADD `rank` INT NOT NULL
     *
     * Only a statement that names such an object moves; `CREATE TABLE orders` reads as it did.
     */
    public const int CURRENT = 8;

    public function __construct(public int $version) {}

    public static function current(): self
    {
        return new self(self::CURRENT);
    }

    /** Whether this version is one this build knows how to read — an unknown version is undetermined, never guessed. */
    public function isKnown(): bool
    {
        return $this->version >= 1 && $this->version <= self::CURRENT;
    }

    public function equals(self $other): bool
    {
        return $this->version === $other->version;
    }
}
