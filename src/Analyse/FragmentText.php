<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node\Arg;
use PhpParser\Node\Expr;
use PHPStan\Analyser\Scope;

/**
 * Which argument of a fragment call carries the raw text, and which its bindings.
 *
 * Two collectors ask it, one per node shape: {@see RawSqlFragmentCollector} for `$builder->whereRaw(…)`
 * and {@see RawSqlModelFragmentCollector} for `Order::whereRaw(…)`. It lives here so the two cannot
 * come to disagree about which calls hand over text: a copy that learned the subquery methods one
 * release later would leave the other spelling silent for that release.
 */
final readonly class FragmentText
{
    /**
     * The raw text this call hands over and the bindings that travel with it, or null for none.
     *
     * A fragment sink takes the text first and its bindings second. A subquery sink takes its text
     * where {@see RawSqlSinks::SUBQUERY_SINKS} says, and only when it is a string: a closure or a
     * builder is the parameterized form of the same call, so asking its type comes before anything
     * else. A call with no argument at all has no text to be right or wrong about.
     *
     * @param  array<Arg>  $arguments
     * @return array{Expr, Expr|null}|null
     */
    public static function of(string $method, array $arguments, Scope $scope): ?array
    {
        if (in_array($method, RawSqlSinks::FRAGMENT_SINKS, true)) {
            return $arguments === [] ? null : [$arguments[0]->value, ($arguments[1] ?? null)?->value];
        }

        $position = RawSqlSinks::SUBQUERY_SINKS[$method] ?? null;
        $subquery = $position === null ? null : self::subquery($arguments, $position);

        if (! $subquery instanceof Expr || $scope->getType($subquery)->isString()->no()) {
            return null;
        }

        // No bindings. The string form has none, and the argument after it is an alias or a join
        // column; reading that as a bindings array would check placeholders against a table name.
        return [$subquery, null];
    }

    /**
     * The subquery argument, by name when the call names it and by position otherwise.
     *
     * A named argument can stand anywhere, and `insertUsing(query: …, columns: […])` is valid PHP.
     * An unpacked argument at the position could be anything, so it is not read as the subquery.
     *
     * @param  array<Arg>  $arguments
     */
    private static function subquery(array $arguments, int $position): ?Expr
    {
        foreach ($arguments as $argument) {
            if ($argument->name?->toString() === 'query') {
                return $argument->value;
            }
        }

        $argument = $arguments[$position] ?? null;

        return $argument !== null && $argument->name === null && ! $argument->unpack ? $argument->value : null;
    }
}
