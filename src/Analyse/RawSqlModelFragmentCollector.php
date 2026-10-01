<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * The fragment sinks called statically on a model: `Order::whereRaw(…)`, `Order::fromSub(…)`.
 *
 * ## What was missing
 *
 *     Order::whereRaw("tenant_id = {$tenant}")->get();
 *
 * is the shortest way to write a raw condition in Eloquent, and `__callStatic` hands it to a new
 * builder exactly as `Order::query()->whereRaw(…)` does. The second spelling was reported and the
 * first was not: {@see RawSqlFragmentCollector} sees method calls, and the only collector of static
 * fragment calls, {@see RawSqlExpressionCollector}, asks whether the class is `DB`.
 *
 * ## What it reads, and who reads it
 *
 * The same names and the same text as the fragment collector — {@see FragmentText} answers both —
 * and rows in the same shape. So the same rules read them: the interpolation rule and the
 * stale-reason rule. The policy rule does not, because a fragment is not a decision about how to
 * talk to the database, however it is spelled.
 *
 * The class has to resolve to a model that forwards the call, through its name or `self`/`static`
 * ({@see ModelForwarding}). A class held in a variable is not read, and neither is a model that
 * declares the method itself.
 *
 * @implements Collector<StaticCall, array{method: string, line: int, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}>
 */
final readonly class RawSqlModelFragmentCollector implements Collector
{
    public function __construct(private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer) {}

    public function getNodeType(): string
    {
        return StaticCall::class;
    }

    /**
     * @return array{method: string, line: int, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (! $node->name instanceof Identifier || ! $node->class instanceof Name) {
            return null;
        }

        $method = $node->name->toString();
        $text = FragmentText::of($method, $node->getArgs(), $scope);

        if ($text === null || ! ModelForwarding::reachesBuilder($scope->resolveTypeByName($node->class), $method)) {
            return null;
        }

        $verdict = $this->analyzer->classify($text[0], $text[1], $scope);

        return [
            'method' => $method,
            'line' => $node->getStartLine(),
            'scope' => $this->scopeName($scope),
            'signal' => $verdict->signal->value,
            'quoted' => $verdict->identifierQuoted,
            'origin' => $verdict->origin->value,
            'reason' => $verdict->reason?->value,
        ];
    }

    /**
     * The finest name this call site can be justified under — `Class::method`, the class, or null.
     *
     * The same format every other collector records, so a rule joining on scope reads one shape
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
