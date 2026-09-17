<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Understanding;

/**
 * One index key position that folds a single column's case, read into what it promises.
 *
 * ## What this answers, and it is not the redundancy question
 *
 * `lower(email)` and `email` are different keys, and {@see IndexComprehension} already compares them
 * as the different things they are — an expression index carried intact needs nothing from this
 * class to be comparable. What no reader could say before is what such a key MEANS when the index is
 * unique: the table guarantees that no two rows share a value once case is folded away, which is a
 * promise the application has to make the same way or it asks a question the index does not answer.
 *
 * So this class reads a key position and says whether it is a plain case fold of one column. It
 * produces no verdict; the rule that consumes it does.
 *
 * ## The forms it knows, every one measured rather than imagined
 *
 * Measured on PostgreSQL 18.4 by creating the index and reading `pg_get_indexdef(indexrelid, n,
 * true)` back — the same per-position text the PostgreSQL catalog reader stores among an index
 * object's `key_columns`. The reader is named in prose rather than as a class reference because this
 * file stays in the core package and that reader lives in a driver one.
 *
 * | column type | written | the key position prints |
 * |---|---|---|
 * | `text` | `lower(body)` | `lower(body)` |
 * | `varchar(255)` | `lower(email)` | `lower(email::text)` |
 * | `char(8)` | `lower(tag)` | `lower(tag::text)` |
 * | `varchar(30)` | `lower("Mixed")` | `lower("Mixed"::text)` |
 * | `varchar(50)` | `UPPER(Display_Name)` | `upper(display_name::text)` |
 *
 * ⚠️ **THE CAST IS THE NORMAL CASE, AND A READER WRITTEN WITHOUT IT MATCHES NOTHING REAL.** Only a
 * `text` column arrives bare; every other string type is coerced, because the function is defined
 * over `text` and the planner records the coercion. Laravel's `string()` column is `varchar(255)`, so
 * the cast form is the one an application actually has — the consumer index this was built for,
 * `CREATE UNIQUE INDEX users_email_lower_unique ON users ((lower(email)))`, arrives as
 * `lower(email::text)`. A pattern accepting only `lower(email)` would pass every test written by the
 * person who typed it and then find nothing at all, which is the silent direction: "no case-folded
 * index here" reads exactly like "this schema has none".
 *
 * **The doubled parentheses that consumer wrote are gone, and that is also measured.** They are
 * required by MySQL for a functional key and accepted by PostgreSQL, so portable migrations carry
 * them — and the server prints the key position without them. Nothing may be matched against what
 * the DDL said.
 *
 * **Case and spelling are normalized by the server**, so `UPPER(Display_Name)` and
 * `upper(display_name)` are one key to any reader. The patterns below are therefore lowercase-only
 * and not case-insensitive: an upper-case spelling is a branch no server can reach, and this package
 * does not carry those (see the note on `!=` in {@see IndexPredicate}).
 *
 * **Only a bare `::text` cast is accepted, which is the only one measured.** A `citext` column needs
 * no cast at all and so arrives bare, which the first form already covers. Any other spelling is a
 * shape nobody has seen, and it is refused rather than guessed at.
 *
 * ## The refusal, and why it is the feature
 *
 * Anything that is not exactly one fold of exactly one column returns null: a nested call, a
 * concatenation, a `COALESCE`, a plain column. Measured, `lower(btrim(email))` prints as
 * `lower(btrim(email::text))` — folded AND trimmed, so the value the index is unique over is not the
 * column's case-folded value and a sentence saying it is would be false. The whole worth of this
 * reading is that the sentence it enables is exact; a fold this class admits it cannot read costs a
 * report line, and one it misreads costs the reader's trust in every other line.
 */
final readonly class CaseFoldedKey
{
    /**
     * A column reference as the server prints one: bare lowercase, or quoted when it is not.
     *
     * The quoted form keeps its quotes, because `"Email"` and `email` are different columns and
     * merging them would name the wrong one in a sentence about a guarantee.
     */
    private const string IDENTIFIER = '(?:[a-z_][a-z0-9_]*|"[^"]+")';

    private function __construct(
        /** The column whose case is folded, spelled as the server spells it. */
        public string $column,
        /** Which direction the fold goes: `lower` or `upper`. */
        public string $fold,
    ) {}

    /**
     * Read one key position, or null when it is not a plain case fold of a single column.
     */
    public static function parse(string $keyPosition): ?self
    {
        $pattern = '/^(lower|upper)\(\s*('.self::IDENTIFIER.')(?:::text)?\s*\)$/';

        if (preg_match($pattern, trim($keyPosition), $matched) !== 1) {
            return null;
        }

        return new self($matched[2], $matched[1]);
    }

    /**
     * The guarantee as a reader wants to hear it, rather than as the server spells it.
     *
     * No backticks and no markup: this sentence reaches a terminal line and a JSON detail, and
     * neither renders them.
     */
    public function describe(): string
    {
        return sprintf('the %s-case form of %s', $this->fold, $this->column);
    }
}
