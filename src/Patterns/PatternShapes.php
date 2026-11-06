<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

/**
 * Reads what an index could serve from the masked text of a query pattern on one table.
 *
 * A pattern is what {@see QueryPatterns} renders: keywords and unquoted names folded to lower case, a
 * quoted name as written, every value a `?` and a list of values one `?`. The reader takes a `SELECT`,
 * an `UPDATE` or a `DELETE` on one table, the conditions of its `WHERE` that are joined by `AND`, and
 * the leading columns of its `ORDER BY`. A condition it does not understand, a function around a column
 * for instance, it leaves out, because no index on the column serves it. A statement it cannot read as
 * one table it answers with the reason, because an index advice on a guess is worse than none.
 */
final class PatternShapes
{
    /** The words that put a second table into the statement. */
    private const array SECOND_TABLE = ['join', 'union', 'intersect', 'except', 'with'];

    /** The words that end a table reference or a condition at the top level. */
    private const array CLAUSES = ['where', 'set', 'group', 'having', 'window', 'order', 'limit', 'offset', 'fetch', 'for', 'returning'];

    /** The comparisons that bound a column. */
    private const array BOUNDS = ['<', '<=', '>', '>='];

    /** The shape of a pattern, or the reason it has none. */
    public static function read(string $pattern): PatternShape|string
    {
        $tokens = self::tokens($pattern);
        $words = array_map(strtolower(...), $tokens);

        if (array_intersect($words, self::SECOND_TABLE) !== [] || self::hasSubquery($words)) {
            return 'it reads more than one table, through a join, a set operation, a common table expression or a subquery';
        }

        $at = match ($words[0] ?? '') {
            'select' => self::topLevel($words, ['from'], 1),
            'delete' => ($words[1] ?? '') === 'from' ? 1 : null,
            'update' => 0,
            default => null,
        };

        if ($at === null) {
            return 'only a select, an update or a delete on a table has a condition an index can serve';
        }

        [$schema, $table, $alias, $next] = self::tableAt($tokens, $words, $at + 1);

        if ($table === null || ($words[$next] ?? '') === ',') {
            return 'it names no single table to read';
        }

        $owners = array_filter([$table, $alias], is_string(...));
        $where = self::topLevel($words, ['where'], $next);
        $order = self::topLevel($words, ['order'], $next);
        $conditions = $where === null ? [] : self::conjuncts($tokens, $words, $where + 1);

        if ($conditions === null) {
            return 'its condition joins two parts with OR, which one index does not serve';
        }

        $shape = self::shapeOf($table, $schema, $conditions, $order === null ? [] : self::order($tokens, $words, $order + 2, $owners), $owners);

        return $shape->columns() === [] ? 'neither its condition nor its order names a column an index can serve' : $shape;
    }

    /**
     * The tokens of a pattern: a quoted name, a word, a two-character operator, or one character.
     *
     * @return list<string>
     */
    private static function tokens(string $pattern): array
    {
        preg_match_all('/"(?:[^"]|"")*"|`(?:[^`]|``)*`|[A-Za-z_][A-Za-z0-9_$]*|<=|>=|<>|!=|::|\S/', $pattern, $matches);

        return $matches[0];
    }

    /** @param  list<string>  $words */
    private static function hasSubquery(array $words): bool
    {
        return array_any($words, static fn (string $word, int $i): bool => $word === '(' && ($words[$i + 1] ?? '') === 'select');
    }

    /**
     * Where the first of the words stands at the top level, from a position on.
     *
     * @param  list<string>  $words
     * @param  list<string>  $wanted
     */
    private static function topLevel(array $words, array $wanted, int $from): ?int
    {
        $depth = 0;

        foreach (array_slice($words, $from, null, true) as $i => $word) {
            $depth += match ($word) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };

            if ($depth === 0 && in_array($word, $wanted, true)) {
                return $i;
            }
        }

        return null;
    }

    /**
     * The table a reference names at a position: its schema, its name, its alias and the position after it.
     *
     * @param  list<string>  $tokens
     * @param  list<string>  $words
     * @return array{0: ?string, 1: ?string, 2: ?string, 3: int}
     */
    private static function tableAt(array $tokens, array $words, int $at): array
    {
        $first = self::name($tokens[$at] ?? '');
        $qualified = ($tokens[$at + 1] ?? '') === '.';
        $table = $qualified ? self::name($tokens[$at + 2] ?? '') : $first;
        $next = $qualified ? $at + 3 : $at + 1;
        $aliased = ($words[$next] ?? '') === 'as';
        $alias = in_array($words[$next] ?? '', self::CLAUSES, true) ? null : self::name($tokens[$aliased ? $next + 1 : $next] ?? '');

        return [$qualified ? $first : null, $table, $alias, $next + ($alias === null ? 0 : ($aliased ? 2 : 1))];
    }

    /** A name as the catalog spells it, from its token, or null where the token is no name. */
    private static function name(string $token): ?string
    {
        return match (true) {
            str_starts_with($token, '"') => str_replace('""', '"', substr($token, 1, -1)),
            str_starts_with($token, '`') => str_replace('``', '`', substr($token, 1, -1)),
            preg_match('/^[a-z_][a-z0-9_$]*$/', $token) === 1 && ! in_array($token, [...self::CLAUSES, 'as', 'and', 'or', 'not', 'is', 'in', 'null', 'between', 'like'], true) => $token,
            default => null,
        };
    }

    /**
     * The conditions of a `WHERE` joined by `AND` at its top level, or null where an `OR` joins two.
     *
     * The `AND` of a `BETWEEN` belongs to it, so it does not split the condition.
     *
     * @param  list<string>  $tokens
     * @param  list<string>  $words
     * @return list<list<string>>|null
     */
    private static function conjuncts(array $tokens, array $words, int $from): ?array
    {
        $conjuncts = [[]];
        $depth = 0;
        $between = false;

        foreach (array_slice($tokens, $from, null, true) as $i => $token) {
            $word = $words[$i];
            $depth += match ($word) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };

            if ($depth === 0 && in_array($word, self::CLAUSES, true)) {
                break;
            }

            if ($depth === 0 && $word === 'or') {
                return null;
            }

            if ($depth === 0 && $word === 'and' && ! $between) {
                $conjuncts[] = [];

                continue;
            }

            $between = $word === 'between' || ($between && $word !== 'and');
            $conjuncts[array_key_last($conjuncts)][] = $token;
        }

        return $conjuncts;
    }

    /**
     * The leading columns of an `ORDER BY` in one direction.
     *
     * @param  list<string>  $tokens
     * @param  list<string>  $words
     * @param  list<string>  $owners
     * @return list<string>
     */
    private static function order(array $tokens, array $words, int $from, array $owners): array
    {
        $columns = [];
        $direction = null;

        foreach (self::items($tokens, $words, $from) as $item) {
            [$column, $length] = self::columnAt($item, 0, $owners);
            $rest = array_map(strtolower(...), array_slice($item, $length));
            $descending = ($rest[0] ?? '') === 'desc';
            $direction ??= $descending;

            if ($column === null || $direction !== $descending || array_diff($rest, ['asc', 'desc', 'nulls', 'first', 'last']) !== []) {
                break;
            }

            $columns[] = $column;
        }

        return $columns;
    }

    /**
     * The items of a list at the top level, up to the clause that ends it.
     *
     * @param  list<string>  $tokens
     * @param  list<string>  $words
     * @return list<list<string>>
     */
    private static function items(array $tokens, array $words, int $from): array
    {
        $items = [[]];
        $depth = 0;

        foreach (array_slice($tokens, $from, null, true) as $i => $token) {
            $depth += match ($words[$i]) {
                '(' => 1,
                ')' => -1,
                default => 0,
            };

            if ($depth === 0 && in_array($words[$i], self::CLAUSES, true)) {
                break;
            }

            if ($depth === 0 && $token === ',') {
                $items[] = [];

                continue;
            }

            $items[array_key_last($items)][] = $token;
        }

        return $items;
    }

    /**
     * The column a reference at a position names, `"t"."c"` or `"c"`, and how many tokens it takes.
     *
     * A reference qualified by anything but the table or its alias names no column of this table.
     *
     * @param  list<string>  $tokens
     * @param  list<string>  $owners
     * @return array{0: ?string, 1: int}
     */
    private static function columnAt(array $tokens, int $at, array $owners): array
    {
        $first = self::name($tokens[$at] ?? '');

        if (($tokens[$at + 1] ?? '') === '.') {
            $column = self::name($tokens[$at + 2] ?? '');

            return [in_array($first, $owners, true) ? $column : null, 3];
        }

        return [$first, 1];
    }

    /**
     * The shape the conditions and the order make, each condition read as a comparison with a value.
     *
     * @param  list<list<string>>  $conditions
     * @param  list<string>  $sort
     * @param  list<string>  $owners
     */
    private static function shapeOf(string $table, ?string $schema, array $conditions, array $sort, array $owners): PatternShape
    {
        $equality = [];
        $range = [];
        $nulls = [];

        foreach ($conditions as $condition) {
            $condition = self::withoutValueCasts($condition);
            $reversed = ($condition[0] ?? '') === '?';
            [$column, $length] = self::columnAt($condition, $reversed ? 2 : 0, $owners);
            $rest = array_map(strtolower(...), $reversed ? [$condition[1] ?? '', '?'] : array_slice($condition, $length));
            $exact = ! $reversed || count($condition) === 2 + $length;

            if ($column === null || ! $exact) {
                continue;
            }

            if ($rest === ['=', '?'] || $rest === ['in', '(', '?', ')']) {
                $equality[] = $column;
            } elseif ((count($rest) === 2 && in_array($rest[0], self::BOUNDS, true) && $rest[1] === '?') || $rest === ['between', '?', 'and', '?']) {
                $range[] = $column;
            } elseif ($rest === ['is', 'null'] || $rest === ['is', 'not', 'null']) {
                $nulls[$column] = $rest === ['is', 'null'];
            }
        }

        return new PatternShape($table, $schema, array_values(array_unique($equality)), array_values(array_unique($range)), $sort, $nulls);
    }

    /**
     * A condition without the casts that follow a value, `? :: date`, which leave the column as it is.
     *
     * @param  list<string>  $condition
     * @return list<string>
     */
    private static function withoutValueCasts(array $condition): array
    {
        $kept = [];
        $skip = 0;

        foreach ($condition as $i => $token) {
            if ($token === '::' && ($condition[$i - 1] ?? '') === '?') {
                $skip = 2;
            }

            if ($skip > 0) {
                $skip--;

                continue;
            }

            $kept[] = $token;
        }

        return $kept;
    }
}
