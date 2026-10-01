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
 * Eloquent's statement sink called statically on a model: `Order::fromQuery(…)`.
 *
 * The model does not declare the method; `__callStatic` forwards it to a new builder, which runs
 * the statement on the model's connection. It is the shortest spelling of the call, and the facade
 * collector cannot see it, because it asks whether the class is `DB`.
 *
 * The class has to resolve to a model, through its name or `self`/`static`. A class held in a
 * variable is not read: nothing here can say which class it is. Which models count, and why one
 * that declares its own `fromQuery()` does not, is {@see ModelForwarding}'s answer, shared with the
 * object spelling in {@see RawSqlEloquentCallCollector}.
 *
 * @implements Collector<StaticCall, array{method: string, line: int, resolved: string, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}>
 */
final readonly class RawSqlEloquentStaticCallCollector implements Collector
{
    public function __construct(private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer) {}

    public function getNodeType(): string
    {
        return StaticCall::class;
    }

    /**
     * @return array{method: string, line: int, resolved: string, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (! $node->name instanceof Identifier || ! $node->class instanceof Name) {
            return null;
        }

        $method = $node->name->toString();

        if (! in_array($method, RawSqlSinks::ELOQUENT_STATEMENT_SINKS, true)) {
            return null;
        }

        if (! ModelForwarding::reachesBuilder($scope->resolveTypeByName($node->class), $method)) {
            return null;
        }

        return EloquentStatementSink::row($node, $method, $scope, $this->analyzer);
    }
}
