<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use Illuminate\Database\Grammar;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\InterpolatedString;
use PHPStan\Analyser\Scope;
use PHPStan\Type\ObjectType;

/**
 * What the engine's own escaping did to a value on its way into statement text — and, just as
 * important, what it did NOT do.
 *
 * ## Why this exists
 *
 * There are positions no engine parameterizes. An identifier, a schema name, a settings name, DDL
 * assembled from an enum: PostgreSQL takes a placeholder in none of them, measured with a positive
 * control — `SELECT 1 FROM ?` is a syntax error while `SELECT ? FROM migrations` runs on the same
 * PDO. So `statement('… = ?', [$value])` is advice that cannot be followed there, and this package's
 * own rule about that is unambiguous: a tool that answers a real finding with an impossible fix
 * reads as one that did not understand the code, and its next finding is believed less.
 *
 * What a project does instead is put the value through the engine's own escaping. This class reads
 * that, and separates the two forms it takes — because they are not equally strong, and pretending
 * they are is how a security rule acquires a false negative.
 *
 * ## The two forms, measured rather than assumed
 *
 * **`Connection::escape()` neutralizes completely.** It is `PDO::quote()` for a string, a cast for
 * an int or a float, a driver literal for a bool, and a refusal for an array, a null byte or invalid
 * UTF-8. The result is a VALUE literal. It cannot change the statement's grammar and it cannot
 * select a different object — which is exactly what a binding guarantees, at a position that accepts
 * no binding. So a value that went through it is no longer raw, and the finding goes.
 *
 * **`Grammar::wrap()` does NOT.** It prevents the breakout and nothing more. Measured against both
 * shipped grammars with real objects:
 *
 *     wrap('x"; DROP TABLE users; --')  ->  "x""; DROP TABLE users; --"     quoted, doubled
 *     wrap('other_schema.secrets')      ->  "other_schema"."secrets"         a DIFFERENT OBJECT
 *     wrap('orders as o')               ->  "orders" as "o"                  an alias appears
 *     wrap(DB::raw($evil))              ->  evil"; DROP TABLE users; --      VERBATIM
 *
 * The first line is the guarantee people mean. The second is the one they forget: `wrap()` splits
 * on `.` and quotes each segment, so a value carrying a dot reaches across schemas — no breakout,
 * but not the author's choice of object either. And the fourth is a plain passthrough: an
 * `Expression` is returned unwrapped, by design, because that is what `DB::raw()` is for.
 *
 * So `wrap()` earns a truthful REMEDY, not silence. Silence would be a false negative on an
 * injection rule, and nothing else in the package would catch it: `DynamicIdentifierCollector`
 * watches `groupBy`, `latest`, `oldest`, `orderBy` and `orderByDesc` — builder methods — and never
 * sees a `DB::statement()` at all.
 *
 * ## Static, and that is a constraint rather than a convenience
 *
 * `ParameterizationAnalyzerTest` holds the classifier to having NO constructor, so that its two
 * consumers — a security rule and a driver-neutral policy rule — share one configuration-free
 * instance and neither inherits the other's configuration. Injecting this class would have grown
 * that constructor. These are pure predicates over a node and a scope with no state to configure,
 * so a static call says the same thing without weakening the guard.
 *
 * ## The direction this class may be wrong in
 *
 * Only one. Every method here may turn a finding OFF where it can prove there is nothing to find,
 * and may never turn an unresolved argument into a pass — the same rule
 * {@see ParameterizationAnalyzer::carriesNoRuntimeValue()} states for itself. An argument whose type
 * is not provably a scalar answers false, and the finding stands.
 */
final readonly class EngineNeutralization
{
    /**
     * Every runtime part of this expression went through `Connection::escape()`.
     *
     * The whole expression is asked, not one part of it: `'X'.$c->escape($a).$b` is not escaped, and
     * a check that answered on the first escaped part it found would say it was.
     */
    public static function valueEscaped(Expr $expr, Scope $scope): bool
    {
        return self::everyRuntimePart(
            $expr,
            $scope,
            static fn (Expr $part): bool => self::isEscapeCall($part, $scope),
        );
    }

    /**
     * Every runtime part of this expression went through `Grammar::wrap()`.
     *
     * A weaker statement than {@see self::valueEscaped()}, and the caller has to treat it as one:
     * it says the value cannot break out of the identifier quoting, never that it cannot choose the
     * object.
     */
    public static function identifierQuoted(Expr $expr, Scope $scope): bool
    {
        return self::everyRuntimePart(
            $expr,
            $scope,
            static fn (Expr $part): bool => self::isWrapCall($part, $scope),
        );
    }

    /**
     * Does every part of the expression that is not literal text satisfy $accept?
     *
     * An expression with NO runtime part at all answers false rather than true. That case is not
     * this class's to decide — a wholly literal statement is already parameterized by
     * {@see ParameterizationAnalyzer}, and answering true here would mean two places claiming the
     * same thing for different reasons.
     *
     * @param  callable(Expr): bool  $accept
     */
    private static function everyRuntimePart(Expr $expr, Scope $scope, callable $accept): bool
    {
        $parts = self::runtimeParts($expr, $scope);

        return $parts !== [] && array_all($parts, $accept);
    }

    /**
     * The parts of the expression that are not literal text.
     *
     * Concatenation and interpolation are walked; anything else is one part, itself. A literal
     * string contributes nothing to smuggle and is dropped here rather than accepted downstream,
     * which keeps `$accept` a question about runtime values only.
     *
     * @return list<Expr>
     */
    private static function runtimeParts(Expr $expr, Scope $scope): array
    {
        if ($scope->getType($expr)->isLiteralString()->yes()) {
            return [];
        }

        if ($expr instanceof Concat) {
            return [...self::runtimeParts($expr->left, $scope), ...self::runtimeParts($expr->right, $scope)];
        }

        if ($expr instanceof InterpolatedString) {
            $parts = [];

            foreach ($expr->parts as $part) {
                // The literal chunks between the braces are their own node type and carry no value.
                // The narrowing is on Expr rather than on that type: a future parser could add a
                // third kind of part, and treating an unknown one as a runtime value is the safe
                // direction — it keeps the finding rather than dropping it.
                if ($part instanceof Expr) {
                    $parts = [...$parts, ...self::runtimeParts($part, $scope)];
                }
            }

            return $parts;
        }

        return [$expr];
    }

    /** A `->escape(…)` on a database connection, with an argument the method's own signature admits. */
    private static function isEscapeCall(Expr $expr, Scope $scope): bool
    {
        return self::isCall($expr, 'escape', [Connection::class, ConnectionInterface::class], $scope)
            && $expr instanceof MethodCall
            && self::takesAScalar($expr, $scope);
    }

    /**
     * A `->wrap(…)` on a query grammar, with a STRING argument.
     *
     * The type check is the whole safety of this one. `wrap()` hands an `Expression` straight back
     * unwrapped — that is what `DB::raw()` exists for — so `wrap(DB::raw($evil))` is a passthrough
     * wearing the shape of an escape. Requiring the argument to be provably a string refuses that,
     * and refuses `mixed` with it.
     */
    private static function isWrapCall(Expr $expr, Scope $scope): bool
    {
        return self::isCall($expr, 'wrap', [Grammar::class], $scope)
            && $expr instanceof MethodCall
            && ($expr->getArgs()[0] ?? null) !== null
            && $scope->getType($expr->getArgs()[0]->value)->isString()->yes();
    }

    /**
     * A method call by name on a receiver of one of the given types.
     *
     * `isSuperTypeOf` rather than a name comparison, and every relevant class rather than one: a
     * connection arrives as `Connection` from `DB::connection()` and as `ConnectionInterface` from a
     * constructor, and listing one would be silent on the other.
     *
     * @param  list<class-string>  $receivers
     */
    private static function isCall(Expr $expr, string $method, array $receivers, Scope $scope): bool
    {
        if (! $expr instanceof MethodCall || ! $expr->name instanceof Identifier) {
            return false;
        }

        if ($expr->name->toString() !== $method) {
            return false;
        }

        $receiver = $scope->getType($expr->var);

        return array_any(
            $receivers,
            static fn (string $class): bool => new ObjectType($class)->isSuperTypeOf($receiver)->yes(),
        );
    }

    /**
     * Is the first argument one of the scalars `escape()` declares it takes?
     *
     * Its signature is `string|float|int|bool|null`, and it THROWS on an array. So an argument the
     * analyzer cannot pin to a scalar is refused here rather than assumed — the refusal costs a
     * finding somebody can exempt, and the assumption would cost the claim this class makes.
     */
    private static function takesAScalar(MethodCall $call, Scope $scope): bool
    {
        $argument = $call->getArgs()[0] ?? null;

        if ($argument === null) {
            return false;
        }

        $type = $scope->getType($argument->value);

        return $type->isString()->yes()
            || $type->isInteger()->yes()
            || $type->isFloat()->yes()
            || $type->isBoolean()->yes();
    }
}
