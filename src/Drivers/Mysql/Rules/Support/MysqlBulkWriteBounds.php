<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

use Pushery\SQLens\Rules\Data\BulkWrite;
use Pushery\SQLens\Rules\Data\BulkWriteBounds;

/**
 * The two bounds a canonical MySQL write can carry.
 *
 * `LIMIT` is the direct one, and MySQL is the engine that has it: Laravel's MySQL grammar emits
 * `->limit(1000)` verbatim onto an `UPDATE` or `DELETE` (measured; PostgreSQL has no such clause
 * and the framework emulates it with a `ctid` subselect instead — see the PostgreSQL sibling).
 *
 * `BETWEEN` is the indirect one, and accepting it is a deliberate leniency: a key-range walk is
 * exactly the chunking pattern the finding recommends, and Laravel emits it with no `LIMIT` at all.
 * Flagging the recommended fix would be crying wolf on the answer. It errs toward a false NEGATIVE
 * — a `BETWEEN` on a non-key column bounds nothing — and that is the right direction for a
 * heuristic whose credibility is the thing it can least afford to spend.
 *
 * ## The `LIMIT` has to be the WRITE's, not a subquery's
 *
 * `UPDATE orders SET status = ? WHERE id IN (SELECT id FROM stale LIMIT 10)` carries a `LIMIT` that
 * bounds the ten rows the subquery returns and says nothing about how many rows the update touches —
 * `stale` could hold ten and match a million. A bare keyword match read that as bounded and went
 * silent over an unbounded write, which is the one finding this rule exists to make. Parenthesized
 * groups are therefore removed before the match, innermost first.
 *
 * That is a tightening: a statement of this shape was silent before 2026-08-24 and is reported now.
 * It is the opposite direction from the `BETWEEN` leniency above and deliberately so — that one
 * accepts a pattern the finding RECOMMENDS, while this one was mis-reading a bound that is not one.
 */
final readonly class MysqlBulkWriteBounds implements BulkWriteBounds
{
    public function bounds(string $masked, bool $isRowSource): bool
    {
        return preg_match('/\bLIMIT\b/', BulkWrite::withoutParenthesizedGroups($masked)) === 1
            || preg_match('/\bBETWEEN\b/', $masked) === 1;
    }
}
