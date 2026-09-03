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
        'UNION', 'INTERSECT', 'EXCEPT', 'WITH',
        'CREATE', 'ALTER', 'DROP', 'TRUNCATE', 'COMMENT',
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
        'CASCADE', 'RESTRICT', 'ADD', 'RENAME', 'TO', 'IF',
        'BEGIN', 'COMMIT', 'ROLLBACK', 'TRANSACTION',
        'INT', 'INTEGER', 'BIGINT', 'SMALLINT', 'TEXT', 'VARCHAR', 'CHAR', 'BOOLEAN',
        'TIMESTAMP', 'DATE', 'TIME', 'NUMERIC', 'DECIMAL', 'JSON', 'JSONB', 'UUID',
    ];
}
