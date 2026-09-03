<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Money;

use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * Money kept in a floating-point column — the rounding nobody reconciles later.
 *
 * ## What goes wrong, and why it is never noticed at the time
 *
 * A binary float cannot represent 0.10 exactly. Add it ten times and the total is not 1.00; it is
 * near enough that every screen shows 1.00 and every comparison against 1.00 fails. The error
 * arrives as one cent on a statement that nobody can reproduce, months after the schema decision,
 * and the person who finds it has no way back to the column.
 *
 * `numeric` / `DECIMAL` store the digits, so the arithmetic is the arithmetic of the invoice.
 *
 * ## The heuristic is a heuristic, and says so
 *
 * There is nothing in a catalog that says "this column holds money". The only signal available is
 * the NAME, which is a guess about intent — so the dictionary carries two confidence levels and
 * this class treats them differently rather than averaging them away.
 *
 * A `strong` term (`price`, `invoice_total`, `rechnungsbetrag`) means money on its own. A `weak`
 * term is ordinary language that is sometimes money: `rate` is an interest rate and a frame rate,
 * `value` names a hundred things, `wert` likewise. A rule that fired on those would be noise, and
 * noise is how a team learns to skip a whole level band.
 *
 * ## The second signal a weak term needs, defined HERE
 *
 * The dictionary states outright that it does not define this: *"a weak term reports only together
 * with a second signal, which the rule defines and this artifact does not"*. Two signals count, and
 * both are STRUCTURAL facts about the table rather than further guesses about the domain:
 *
 * - **A sibling currency column.** A table that stores a currency stores money in it. This is the
 *   strongest evidence a catalog can offer, because it is somebody else's explicit statement.
 * - **A `cents` segment in the name.** `balance_cents` is a minor-unit amount whatever `balance`
 *   means elsewhere.
 *
 * A suffix of `_amount` is deliberately NOT a second signal, even though it looks like one: `amount`
 * is itself a weak term, so "the name ends in `_amount`" would let a weak term vouch for itself and
 * the confidence split would stop meaning anything.
 */
final readonly class FloatingMoneyColumns
{
    /**
     * The canonical types that cannot hold money exactly.
     *
     * Measured on both servers rather than taken from the type list. PostgreSQL reports `real` and
     * `double precision`, and its `float` is an alias resolved at parse time — a column declared
     * `float` comes back as `double precision`, so `float` never reaches a rule from that engine.
     * MySQL reports `float` and `double`, and the canonicalizer maps only the second onto
     * `double precision`. So all three spellings are needed, and each of them is real.
     *
     * @var list<string>
     */
    public const array FLOATING = ['real', 'double precision', 'float'];

    /**
     * The column names that make a table's other names readable as money.
     *
     * @var list<string>
     */
    private const array CURRENCY_NAMES = ['currency', 'currency_code', 'waehrung', 'währung'];

    /**
     * Every floating-point column on this table whose name reads as money.
     *
     * @return array<string, string> column name => the floating type it carries, sorted by column
     */
    public static function on(SchemaObject $table, MoneyColumnDictionary $dictionary): array
    {
        $columns = ForeignKeyIndexCoverage::parse($table->getString('column_types') ?? '');
        $hasCurrencyColumn = self::hasCurrencyColumn(array_keys($columns));
        $found = [];

        foreach ($columns as $column => $types) {
            $type = mb_strtolower($types[0] ?? '');
            $name = (string) $column;

            if (! in_array($type, self::FLOATING, true)) {
                continue;
            }

            if ($dictionary->isStrong($name) || ($dictionary->isWeak($name) && self::secondSignal($name, $hasCurrencyColumn))) {
                $found[$name] = $type;
            }
        }

        ksort($found);

        return $found;
    }

    /**
     * Whether a weak term on this column is corroborated by something structural.
     *
     * @param  bool  $hasCurrencyColumn  whether the table carries a currency column at all
     */
    private static function secondSignal(string $column, bool $hasCurrencyColumn): bool
    {
        return $hasCurrencyColumn || in_array('cents', self::segments($column), true);
    }

    /** @param  list<array-key>  $columns */
    private static function hasCurrencyColumn(array $columns): bool
    {
        return array_any($columns, fn (int|string $column): bool => array_intersect(self::segments((string) $column), self::CURRENCY_NAMES) !== []);
    }

    /**
     * A column name as its underscore-separated segments, lowercased.
     *
     * Segments rather than a substring test, matching the dictionary's own stated rule: `rating` is
     * not `rate`, and `currency_rate_id` should not make every column on the table look monetary
     * through a careless `str_contains`.
     *
     * @return list<string>
     */
    private static function segments(string $column): array
    {
        return array_values(array_filter(explode('_', mb_strtolower(trim($column)))));
    }
}
