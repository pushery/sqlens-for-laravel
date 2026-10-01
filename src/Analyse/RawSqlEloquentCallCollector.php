<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;

/**
 * Eloquent's statement sink reached on an object: `->fromQuery()` on a builder, a relation or a
 * model instance.
 *
 * ## What was missing
 *
 *     Order::query()->fromQuery("select * from orders where email = '{$email}'");
 *
 * hands a complete statement to the model's connection, and no collector saw it. The connection
 * collector waits for a connection receiver, the fragment collector for a fragment name, and the
 * facade collector for a static call on `DB`. A statement built from a request value, in the most
 * Eloquent-looking spelling there is, produced a clean file.
 *
 * ## The receiver decides alone
 *
 * Like {@see RawSqlPdoCallCollector} and unlike {@see RawSqlConnectionCallCollector}, there is no
 * branch that lets the name speak for a receiver nobody can resolve. `fromQuery` is also an
 * ordinary name for a named constructor, and a finding on every one of those is how the suite gets
 * switched off. Which receivers count is {@see EloquentStatementSink}'s answer, shared with the
 * static spelling in {@see RawSqlEloquentStaticCallCollector}.
 *
 * @implements Collector<MethodCall, array{method: string, line: int, resolved: string, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}>
 */
final readonly class RawSqlEloquentCallCollector implements Collector
{
    public function __construct(private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer) {}

    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    /**
     * @return array{method: string, line: int, resolved: string, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (! $node->name instanceof Identifier) {
            return null;
        }

        $method = $node->name->toString();

        if (! in_array($method, RawSqlSinks::ELOQUENT_STATEMENT_SINKS, true)) {
            return null;
        }

        if (! EloquentStatementSink::reachedOn($scope->getType($node->var), $method)) {
            return null;
        }

        return EloquentStatementSink::row($node, $method, $scope, $this->analyzer);
    }
}
