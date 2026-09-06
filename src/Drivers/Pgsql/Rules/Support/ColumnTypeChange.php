<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * The column, the target type and the whole tail of an `ALTER COLUMN … TYPE` — parsed ONCE, for
 * every rule and template that has a question about it.
 *
 * ## Two questions, one parse
 *
 * Three readers ask about this clause and they do not ask the same thing:
 *
 * - `PG.L2.TYPE_CHANGE_REWRITE` needs the whole tail, **including a trailing `USING`**, because a
 *   `USING` expression forces a table rewrite unconditionally — that is its verdict.
 * - `PG.L4.TYPE_NARROWING` needs the bare target type, **excluding** the `USING`, because the
 *   narrowing matrix is keyed on the type alone.
 * - Both remediations need the COLUMN, which neither rule used to keep.
 *
 * For a while the two rules each carried their own `preg_match` over the same string. That is two
 * patterns which agree today and disagree the first time either is touched — with each looking
 * correct on its own, and the symptom being one rule silently answering a different question than
 * it asks.
 *
 * This class does not merge the two questions; it removes the second PARSE. One pattern reads the
 * clause and offers both projections, so a difference between them is a difference this file
 * decided rather than an accident of two regexes drifting.
 *
 * It reads the CANONICAL form — where `ALTER COLUMN` and `TYPE` are normalized keywords — never
 * Laravel's grammar output.
 */
final readonly class ColumnTypeChange
{
    private function __construct(
        /** The column being retyped, unquoted, exactly as the canonical statement names it. */
        public string $column,
        /**
         * Everything after `TYPE`, verbatim — the target type AND any `USING` clause behind it.
         *
         * The rewrite question turns on this: `USING` forces a full-table rewrite whatever the
         * types are, so a reader that only saw the type would miss the decisive part.
         */
        public string $rest,
    ) {}

    /**
     * The TARGET type alone: the tail cut at a `USING` clause or a following `ALTER` clause.
     *
     * What both matrices are keyed on. Derived rather than separately parsed, so it cannot
     * disagree with {@see $rest} about where the type ends.
     *
     * ⚠️ The comma that ends the type is a STRUCTURAL one, and a plain split on the character
     * cannot tell it from the one inside `numeric(10, 2)`. That mattered more than a lost digit:
     * `numeric` is in the rewrite list, so cutting at the first comma handed the matrix
     * `numeric(10`, which it does not recognize — a full table rewrite reporting as "cannot
     * classify from the migration alone". The depth scan below is why the specifier survives.
     */
    public function targetType(): string
    {
        $head = $this->headBeforeFollowingClause();

        $type = preg_split('/\s+USING\b/', $head, 2);

        return trim($type === false ? $head : $type[0]);
    }

    /**
     * The tail up to the comma that separates one `ALTER TABLE` subcommand from the next — the
     * first comma at parenthesis depth zero, or the whole tail when there is none.
     */
    private function headBeforeFollowingClause(): string
    {
        $depth = 0;

        foreach (str_split($this->rest) as $offset => $character) {
            if ($character === '(') {
                $depth++;
            } elseif ($character === ')') {
                $depth = max(0, $depth - 1);
            } elseif ($character === ',' && $depth === 0) {
                return substr($this->rest, 0, $offset);
            }
        }

        return $this->rest;
    }

    /** Whether the change carries a `USING` expression — which forces a rewrite on its own. */
    public function hasUsingClause(): bool
    {
        return preg_match('/\bUSING\b/', $this->rest) === 1;
    }

    /** The retyping this statement performs, or null when it performs none. */
    public static function of(MigrationStatementView $statement): ?self
    {
        if (! $statement->is(StatementKind::AlterTable)) {
            return null;
        }

        if (preg_match('/\bALTER COLUMN\s+(\S+)\s+TYPE\s+(.+)$/', $statement->canonical, $matches) !== 1) {
            return null;
        }

        return new self(trim($matches[1], '"'), $matches[2]);
    }
}
