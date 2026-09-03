<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Rules\Data\BulkWrite;
use Pushery\SQLens\Rules\Data\BulkWriteBounds;

/**
 * The bounds a canonical PostgreSQL write can carry — and the first one does not look like a bound.
 *
 * **PostgreSQL has no `LIMIT` on `UPDATE` or `DELETE`.** So Laravel compiles the same `->limit(1000)`
 * call into a `ctid` subselect, and that is what a chunked backfill actually looks like on this
 * engine. Read straight out of the framework's `PostgresGrammar`:
 *
 * ```php
 * // compileUpdateWithJoinsOrLimit()
 * return "update {$table} set {$columns} where {$this->wrap('ctid')} in ({$selectSql})";
 * ```
 *
 * which produces
 *
 * ```sql
 * update "orders" set "status" = ? where "ctid" in (select "orders"."ctid" from "orders" where … limit 1000)
 * ```
 *
 * A reader that looked for a top-level `LIMIT` — the MySQL signal — would find one here too, inside
 * the subselect, and would be right by accident. It would also accept
 * `UPDATE … WHERE id IN (SELECT id FROM other LIMIT 10)`, where the `LIMIT` bounds the SUBQUERY and
 * says nothing about the rows written. So the `ctid` shape is matched as a shape rather than as a
 * keyword: it is the one form in which a `LIMIT` on this engine really does bound the write.
 *
 * `BETWEEN` is the second, and it is the same deliberate leniency the MySQL sibling makes: a
 * key-range walk is exactly the chunking pattern the finding recommends, and flagging the
 * recommended fix is how a linter gets switched off. It errs toward a false NEGATIVE — a `BETWEEN`
 * on a non-key column bounds nothing — which is the right direction for a heuristic whose
 * credibility is the thing it can least afford to spend.
 *
 * ## The one place a plain `LIMIT` DOES bound a PostgreSQL write
 *
 * `INSERT INTO archive (…) SELECT … FROM orders LIMIT 1000` is ordinary PostgreSQL, and the `LIMIT`
 * bounds exactly the rows written. Refusing it here reported the chunked copy this rule's own advice
 * recommends — a false positive on the recommended fix, which is the failure the `BETWEEN` leniency
 * two paragraphs up exists to avoid, and it was live until 2026-08-24.
 *
 * It is accepted only for a row source, and only at the TOP LEVEL. Parenthesized groups are removed
 * before the match, so `INSERT … SELECT … WHERE id IN (SELECT id FROM stale LIMIT 10)` stays
 * unbounded: that `LIMIT` bounds the subquery and says nothing about how many rows the INSERT
 * writes.
 */
final readonly class PgsqlBulkWriteBounds implements BulkWriteBounds
{
    public function bounds(string $masked, bool $isRowSource): bool
    {
        if (preg_match('/\bWHERE\b\s+"?ctid"?\s+IN\s*\(\s*SELECT\b/i', $masked) === 1) {
            return true;
        }

        if ($isRowSource && preg_match('/\bLIMIT\b/', BulkWrite::withoutParenthesizedGroups($masked)) === 1) {
            return true;
        }

        return preg_match('/\bBETWEEN\b/', $masked) === 1;
    }
}
