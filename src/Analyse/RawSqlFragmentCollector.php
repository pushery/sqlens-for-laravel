<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Database\Connection;
use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;

/**
 * The fluent half: `->whereRaw()`, `->selectRaw()` and the rest of the family that splices raw text
 * into a statement the query builder assembles.
 *
 * ## Why it is a second collector rather than a wider first one
 *
 * PHPStan's registry does not walk node subclasses — measured — so a collector registered for
 * `StaticCall` never sees a `MethodCall` however broadly its node type is declared. One collector
 * per node shape is the only arrangement that sees both, and the vocabulary they share lives in
 * {@see RawSqlSinks} so the two cannot drift about which methods count.
 *
 * ## Three receivers, all measured rather than assumed
 *
 * Against `laravel/framework` v13.23.0, with Larastan loaded:
 *
 *     DB::table('orders')     →  Illuminate\Database\Query\Builder
 *     Order::query()          →  Illuminate\Database\Eloquent\Builder<Order>
 *     $order->lines()         →  Illuminate\Database\Eloquent\Relations\HasMany<Line, Order>
 *
 * The Eloquent case is the one a type check gets wrong by accident: `Eloquent\Builder` does NOT
 * declare `whereRaw()` — it forwards through `__call` — so a collector that asked the class for the
 * method would be silent on every Eloquent call site in a codebase. It asks the SUBJECT's type
 * instead, which resolves through Larastan's knowledge, and a generic instantiation still answers
 * as a subtype of the bare class.
 *
 * ## The false-positive fence, and the state it must not swallow
 *
 * A `whereRaw()` on a resolved, foreign class is **not** a call site: a codebase full of
 * repositories and collections would otherwise be collected wholesale. But a receiver that resolves
 * to NOTHING is a different statement — it may well be a query builder — so it is recorded as
 * `undetermined` with {@see UndeterminedReason::ReceiverTypeUnknown} rather than discarded. Silently
 * dropping it is exactly how a real call site disappears from a report that looks complete.
 *
 * ## Why the payload is an array and not the value object the plan asked for
 *
 * Collected data crosses a process boundary — PHPStan analyses in parallel workers and serializes
 * what a collector returns. A value object does not survive that reliably, so the shape is plain
 * data and the rules read it by key.
 *
 * @implements Collector<MethodCall, array{method: string, line: int, scope: string|null, signal: string, origin: string, reason: string|null}>
 */
final readonly class RawSqlFragmentCollector implements Collector
{
    public function __construct(private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer) {}

    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    /**
     * @return array{method: string, line: int, scope: string|null, signal: string, origin: string, reason: string|null}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (! $node->name instanceof Identifier) {
            // A dynamic method name — `$builder->{$method}(…)`. Nothing here says it is a raw call
            // site, and guessing would collect every dynamic dispatch in the codebase.
            return null;
        }

        $method = $node->name->toString();

        if (! in_array($method, RawSqlSinks::FRAGMENT_SINKS, true)) {
            return null;
        }

        $arguments = $node->getArgs();

        if ($arguments === []) {
            return null;
        }

        $receiver = $scope->getType($node->var);

        if ($receiver->getObjectClassNames() === []) {
            // Resolved to nothing at all. Not "somebody else's class" — nobody's.
            return $this->undeterminedReceiver($method, $node->getStartLine(), $scope);
        }

        if (! $this->isRawTextReceiver($method, $receiver)) {
            return null;
        }

        $verdict = $this->analyzer->classify(
            $arguments[0]->value,
            $arguments[1]->value ?? null,
            $scope,
        );

        return [
            'method' => $method,
            'line' => $node->getStartLine(),
            'scope' => $this->scopeName($scope),
            'signal' => $verdict->signal->value,
            'origin' => $verdict->origin->value,
            'reason' => $verdict->reason?->value,
        ];
    }

    /**
     * @return array{method: string, line: int, scope: string|null, signal: string, origin: string, reason: string|null}
     */
    private function undeterminedReceiver(string $method, int $line, Scope $scope): array
    {
        return [
            'method' => $method,
            'line' => $line,
            'scope' => $this->scopeName($scope),
            'signal' => 'undetermined',
            // Not a claim about the SQL — nothing looked at it. The origin says the shape could not
            // be read, which is true of the argument as much as of the receiver here.
            'origin' => 'unknown_variable',
            'reason' => UndeterminedReason::ReceiverTypeUnknown->value,
        ];
    }

    /**
     * Does this receiver really carry this member of the family?
     *
     * Asked per METHOD rather than once for the family, because one member does not live where the
     * others do. `raw()` is declared on `Connection` as well as on the query builder — measured
     * against v13.23.0 — and `$connection->raw("… {$value}")` is the same defect written one
     * receiver over. The other nine exist only on the builder, so widening the check for all of
     * them would accept a receiver on which the call cannot be written at all: not a false positive
     * anybody would hit, but a claim this class would be making without evidence.
     *
     * `isSuperTypeOf` rather than a name comparison, so a generic `Eloquent\Builder<Order>` and every
     * concrete `Relation` subclass answer yes without this class listing them. Listing them would be
     * a second vocabulary that goes stale the first time somebody writes a custom relation.
     */
    private function isRawTextReceiver(string $method, Type $receiver): bool
    {
        $carriers = [QueryBuilder::class, EloquentBuilder::class, Relation::class];

        if ($method === 'raw') {
            $carriers[] = Connection::class;
        }

        return array_any($carriers, fn (string $class): bool => new ObjectType($class)->isSuperTypeOf($receiver)->yes());
    }

    /**
     * The finest name this call site can be attributed to — `Class::method`, the class, or null.
     *
     * The same shape the statement collector records, so a rule joining on scope reads one format
     * whichever collector produced the row.
     */
    private function scopeName(Scope $scope): ?string
    {
        $class = $scope->getClassReflection()?->getName();

        if ($class === null) {
            return null;
        }

        $function = $scope->getFunctionName();

        return $function === null ? $class : $class.'::'.$function;
    }
}
