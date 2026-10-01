<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Relations\Relation;
use PhpParser\Node\Expr\CallLike;
use PHPStan\Analyser\Scope;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;
use PHPStan\Type\VerbosityLevel;

/**
 * What the two collectors of Eloquent's statement sink share: which receivers reach it, and the row
 * a call produces.
 *
 * `Order::fromQuery(…)` is a static call and `Order::query()->fromQuery(…)` a method call, and a
 * PHPStan collector sees one node shape. So there are two collectors
 * ({@see RawSqlEloquentStaticCallCollector}, {@see RawSqlEloquentCallCollector}) and one answer
 * here, because two copies of "which model reaches the builder" would come to disagree about it.
 *
 * ## Which receivers reach it
 *
 * An Eloquent builder declares the method. A relation and a model do not: they forward the call to
 * the builder, and both count. Which models forward is {@see ModelForwarding}'s answer, shared with
 * the fragment collector that reads `Order::whereRaw(…)`.
 *
 * A receiver that resolves to nothing is never enough. The name is shared with those named
 * constructors, so it is no evidence on its own — see {@see RawSqlSinks::ELOQUENT_STATEMENT_SINKS}.
 */
final readonly class EloquentStatementSink
{
    /** Does a call of `$method` on an object of this type reach Eloquent's statement sink? */
    public static function reachedOn(Type $receiver, string $method): bool
    {
        $forwards = array_any(
            [EloquentBuilder::class, Relation::class],
            static fn (string $class): bool => new ObjectType($class)->isSuperTypeOf($receiver)->yes(),
        );

        return $forwards || ModelForwarding::reachesBuilder($receiver, $method);
    }

    /**
     * The row a statement collector records, in the shape the rules read from every one of them.
     *
     * The statement comes first and its bindings second, as on a connection:
     * `fromQuery($query, $bindings = [])`. A call with no argument has no statement to classify, so
     * it is `undetermined` rather than absent, the same answer the facade collector gives.
     *
     * @return array{method: string, line: int, resolved: string, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}
     */
    public static function row(CallLike $node, string $method, Scope $scope, ParameterizationAnalyzer $analyzer): array
    {
        $arguments = $node->getArgs();

        $verdict = $arguments === []
            ? null
            : $analyzer->classify($arguments[0]->value, ($arguments[1] ?? null)?->value, $scope);

        return [
            'method' => $method,
            'line' => $node->getStartLine(),
            'resolved' => $scope->getType($node)->describe(VerbosityLevel::typeOnly()),
            'signal' => $verdict?->signal->value ?? 'undetermined',
            'quoted' => $verdict->identifierQuoted ?? false,
            'origin' => $verdict?->origin->value ?? 'unknown_variable',
            'reason' => $verdict instanceof ParameterizationVerdict
                ? $verdict->reason?->value
                : UndeterminedReason::ArgumentTypeUnresolved->value,
            'scope' => self::scopeName($scope),
        ];
    }

    /**
     * The finest name this call site can be justified under — `Class::method`, the class, or null.
     *
     * The same format every other collector records, so a rule joining on scope reads one shape
     * whichever collector produced the row.
     */
    private static function scopeName(Scope $scope): ?string
    {
        $class = $scope->getClassReflection()?->getName();

        if ($class === null) {
            return null;
        }

        $function = $scope->getFunctionName();

        return $function === null ? $class : $class.'::'.$function;
    }
}
