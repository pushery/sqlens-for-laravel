<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Data;

/**
 * What a canonical data statement says about how much of a table it will touch — and, as always
 * here, what it does not say.
 *
 * The statement settles two things and only two: whether it is a bulk write at all, and whether
 * anything in it BOUNDS the number of rows. It settles nothing about how many rows that is. That
 * asymmetry is the whole reason the rule reading this is a heuristic rather than a fact.
 *
 * ## Why it parses the CANONICAL form
 *
 * The canonicalization has already folded keyword casing and normalized identifier quoting, so
 * `LIMIT` is `LIMIT` however the migration spelled it, and a column actually NAMED `limit` is
 * quoted and cannot be mistaken for the clause. Matching Laravel's raw grammar output instead
 * would break the day the framework changes a space — and would meanwhile be matching the
 * formatter rather than the SQL.
 *
 * Both words this reads were MISSING from the MySQL keyword list until this class needed them: the
 * coverage guard's corpus is generated from the schema builder, so no data statement had ever
 * reached it and `limit`/`between` came out unfolded. One statement, two canonical forms, two
 * fingerprints. The guard now carries a data corpus too.
 *
 * ## What is shared here, and what deliberately is not
 *
 * WHAT a bulk write is — an `UPDATE`/`DELETE` carrying a predicate, or an `INSERT … SELECT` — is the
 * same question on both engines, and it is answered once, here. Whether the statement is BOUNDED is
 * not: MySQL writes `LIMIT` and PostgreSQL cannot, so that half arrives as a
 * {@see BulkWriteBounds} the driver supplies. A single reader looking for both signals on both
 * engines would accept, on each, a bound its own server has no way to express.
 */
final readonly class BulkWrite
{
    private function __construct(
        /**
         * Whether the rows come from a SELECT — an `INSERT … SELECT`, Laravel's `insertUsing()`.
         *
         * Kept apart from an `UPDATE`/`DELETE` because the advice differs: there is no `LIMIT` to
         * add to the write, the bound has to go on the SELECT that feeds it.
         */
        public bool $isRowSource,
        /** Whether the statement carries something that bounds the rows it touches. */
        private bool $bounded,
    ) {}

    /**
     * Read a canonical statement as a bulk write, or null when it is not one.
     *
     * An `UPDATE` or `DELETE` with NO `WHERE` is deliberately not one: that statement's problem is
     * that it touches every row whether or not that was meant, which is a correctness question
     * `GEN.L1.DML_WITHOUT_WHERE` owns at level 1. Returning it here too would put two findings on
     * one statement, and a report that says the same thing twice teaches its reader to skim.
     *
     * A plain `INSERT … VALUES` is not one either — it writes exactly the rows written out in it.
     */
    public static function parse(string $canonical, BulkWriteBounds $bounds): ?self
    {
        $masked = self::withoutStringLiterals($canonical);

        if (preg_match('/^INSERT INTO \S+.*\bSELECT\b/', $masked) === 1) {
            return new self(true, $bounds->bounds($masked, true));
        }

        if (preg_match('/^(?:UPDATE|DELETE FROM) \S+/', $masked) !== 1) {
            return null;
        }

        // No predicate at all is the other rule's finding, not this one's.
        return preg_match('/\bWHERE\b/', $masked) === 1
            ? new self(false, $bounds->bounds($masked, false))
            : null;
    }

    /** Whether anything in the statement bounds the number of rows it touches. */
    public function isBounded(): bool
    {
        return $this->bounded;
    }

    /**
     * The statement with every parenthesized group removed, innermost first.
     *
     * What it is for: telling a bound on the WRITE apart from a bound on a subquery. `LIMIT 10` in
     * `WHERE id IN (SELECT id FROM stale LIMIT 10)` bounds the ten rows the subquery returns and
     * says nothing about how many rows the write touches — a statement that matched a bare `LIMIT`
     * would call that bounded and go silent over an unbounded write, which is the finding this rule
     * exists to make.
     *
     * Iterative rather than one pattern, because regular expressions cannot count: nesting is
     * removed one level at a time until nothing changes. The loop terminates because every pass
     * either shortens the string or matches nothing.
     */
    public static function withoutParenthesizedGroups(string $masked): string
    {
        do {
            $shorter = preg_replace('/\([^()]*\)/', ' ', $masked) ?? $masked;
            $changed = $shorter !== $masked;
            $masked = $shorter;
        } while ($changed);

        return $masked;
    }

    /**
     * The statement with its string literals blanked out.
     *
     * Not caution for its own sake: the canonicalization leaves literal CONTENT untouched by
     * design, because inside quotes a word is data rather than syntax. A row whose value is
     * `'no limit'` would otherwise read as a bounded write.
     */
    private static function withoutStringLiterals(string $canonical): string
    {
        return preg_replace("/'(?:[^']|'')*'/", "''", $canonical) ?? $canonical;
    }
}
