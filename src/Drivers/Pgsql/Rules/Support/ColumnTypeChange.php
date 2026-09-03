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
     * What the narrowing matrix is keyed on. Derived rather than separately parsed, so it cannot
     * disagree with {@see $rest} about where the type ends.
     */
    public function targetType(): string
    {
        $type = preg_split('/\s+USING\b|,/', $this->rest, 2);

        return trim($type === false ? $this->rest : $type[0]);
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
