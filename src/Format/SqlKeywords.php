<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * The keyword vocabulary the pure-PHP formatter recognizes.
 *
 * ## Why a list and not a grammar
 *
 * A grammar would let this formatter reason about structure, and a grammar for two dialects of SQL
 * is a project of its own — one this package deliberately does not take on, because the external
 * backends behind the same seam already have one. What the pure-PHP core promises is narrower and
 * always available: consistent casing, consistent indentation, one clause per line.
 *
 * ## Why the list is CLOSED, and what that costs
 *
 * A word not in it is left exactly as written. That is the safe direction — an unrecognized keyword
 * keeps the author's casing, which is at worst inconsistent — whereas a list that guessed would
 * upper-case a column called `state` and produce a diff nobody asked for on a schema nobody
 * changed.
 *
 * The cost is real and is paid knowingly: a project using a keyword this list does not know sees it
 * left alone, and the fix is one line here rather than a report they have to interpret.
 */
final readonly class SqlKeywords
{
    /**
     * Words that begin a clause, and therefore begin a line.
     *
     * Ordered by nothing in particular — it is a membership test. What matters is that each entry
     * is a word after which a reader expects a new thought, because that is the whole of what this
     * formatter's layout decides.
     *
     * @var list<string>
     */
    public const array CLAUSE_STARTERS = [
        'SELECT', 'FROM', 'WHERE', 'GROUP', 'HAVING', 'ORDER', 'LIMIT', 'OFFSET',
        'INSERT', 'UPDATE', 'DELETE', 'VALUES', 'SET', 'RETURNING',
        'JOIN', 'INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS', 'ON', 'USING',
        'UNION', 'INTERSECT', 'EXCEPT', 'WITH', 'NATURAL',
        'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'COMMENT',
    ];

    /**
     * The words of ALL that MySQL does not reserve, and which therefore can name a table unquoted.
     *
     * On MySQL they keep the case they were written in. A table name there is compared by case on
     * Linux (`lower_case_table_names=0`, the server default), so `from comment` upper-cased is
     * `FROM COMMENT`, a different table. On PostgreSQL an unquoted identifier folds to lower case, and
     * the question does not arise.
     *
     * Measured, not recalled: `information_schema.KEYWORDS` on MySQL 8.4.10 marks 18 of these as
     * non-reserved, and ILIKE, JSONB and UUID are no MySQL keywords at all. The MySQL lane holds this
     * list against the server it runs on.
     *
     * @var list<string>
     */
    public const array MYSQL_UNRESERVED = [
        'ANY', 'BEGIN', 'BOOLEAN', 'COMMENT', 'COMMIT', 'DATE', 'END', 'FULL', 'ILIKE', 'JSON', 'JSONB',
        'OFFSET', 'RETURNING', 'ROLLBACK', 'TEXT', 'TIME', 'TIMESTAMP', 'TRANSACTION', 'TRUNCATE', 'UUID',
        'VIEW',
    ];

    /**
     * A clause keyword that CONTINUES the clause the word before it opened, keyed by that keyword.
     *
     * Every word in CLAUSE_STARTERS breaks a line on its own, and several of them are the second
     * word of one clause. Measured before this list existed: `INNER` and `JOIN` on two lines,
     * `LEFT outer` over `JOIN`, `DELETE` over `FROM t`, a foreign key's `ON` over `DELETE CASCADE`,
     * `do` over `UPDATE` in an upsert, `for` over `UPDATE`, `COMMENT` over `ON TABLE`.
     *
     * @var array<string, list<string>>
     */
    public const array CLAUSE_CONTINUATIONS = [
        'JOIN' => ['INNER', 'LEFT', 'RIGHT', 'FULL', 'CROSS', 'OUTER', 'NATURAL'],
        'FROM' => ['DELETE'],
        'DELETE' => ['ON'],
        'UPDATE' => ['ON', 'DO', 'FOR'],
        'ON' => ['COMMENT'],
    ];

    /**
     * Every keyword, clause starters included.
     *
     * Deliberately not exhaustive for either engine, and that is the closed-list decision above
     * rather than an oversight: these are the words that appear in migrations and in the statements
     * a migration produces, which is the SQL this package formats.
     *
     * @var list<string>
     */
    public const array ALL = [
        ...self::CLAUSE_STARTERS,
        'AND', 'OR', 'NOT', 'NULL', 'IS', 'IN', 'LIKE', 'ILIKE', 'BETWEEN', 'EXISTS',
        'AS', 'DISTINCT', 'ALL', 'ANY', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
        'ASC', 'DESC', 'BY', 'INTO', 'TABLE', 'INDEX', 'VIEW', 'COLUMN', 'CONSTRAINT',
        'PRIMARY', 'FOREIGN', 'KEY', 'UNIQUE', 'CHECK', 'DEFAULT', 'REFERENCES',
        'CASCADE', 'RESTRICT', 'ADD', 'RENAME', 'TO', 'IF', 'OUTER', 'FOR',
        'BEGIN', 'COMMIT', 'ROLLBACK', 'TRANSACTION',
        'INT', 'INTEGER', 'BIGINT', 'SMALLINT', 'TEXT', 'VARCHAR', 'CHAR', 'BOOLEAN',
        'TIMESTAMP', 'DATE', 'TIME', 'NUMERIC', 'DECIMAL', 'JSON', 'JSONB', 'UUID',
    ];
}
