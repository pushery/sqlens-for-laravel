<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Database\Connection;
use Illuminate\Database\ConnectionInterface;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;
use PHPStan\Type\VerbosityLevel;

/**
 * Statement sinks reached on a connection INSTANCE — the form the suite was blind to.
 *
 * ## What was missing, and how silent it was
 *
 * `RawSqlCallCollector` sees `StaticCall`, so it covers `DB::statement(…)`. `RawSqlFragmentCollector`
 * sees `MethodCall`, but only for the nine FRAGMENT sinks. The two vocabularies are disjoint, which
 * left a hole neither could reach: `$connection->statement(…)` is a `MethodCall` carrying a
 * STATEMENT name. The fragment collector rejects the name; the statement collector never sees the
 * node shape.
 *
 * So this reported nothing at all:
 *
 *     DB::connection('reporting')->statement("update orders set status = '{$value}'");
 *
 * An obvious interpolation in an `UPDATE`, and a clean-looking file. Both spellings — a connection
 * resolved by name and a `Connection $db` injected into a constructor — are ordinary Laravel.
 *
 * ## Why this is a third collector rather than a wider list somewhere
 *
 * PHPStan's registry does not walk subclasses, so one collector per node shape is the only way to
 * see more than one. And widening `RawSqlFragmentCollector` to accept statement names would give it
 * two receiver vocabularies and two data shapes in one class; the fragment shape does not carry
 * `resolved`, which the statement rules read.
 *
 * ## The false-positive fence, which is the whole difficulty
 *
 * Five of the twelve statement sinks are ALSO declared on a query builder or the model — measured
 * against the installed framework, not remembered ({@see RawSqlSinks::CONNECTION_ONLY_SINKS}). A
 * collector matching the bare name on any `MethodCall` would fire on every `$builder->select('id')`
 * and every `$model->update([...])` in the codebase.
 *
 * So the receiver decides, and there are exactly three answers:
 *
 *   - it resolves to a connection ⇒ collect and classify, the same as the facade form;
 *   - it resolves to something else ⇒ not a raw-SQL call site, and silence is correct;
 *   - it resolves to NOTHING ⇒ the name decides. A name only a connection declares is evidence by
 *     itself and produces an honest `undetermined`; a name every builder shares is not, and a
 *     finding there would land on ordinary code in every project.
 *
 * That third branch is the one worth stating plainly: it trades a little recall for the suite still
 * being switched on next week. The gap it leaves — an unresolved receiver calling `->update()` with
 * interpolated text — is real, and it is narrower than the gap this whole class closes.
 *
 * @implements Collector<MethodCall, array{method: string, line: int, resolved: string, scope: string|null, signal: string, origin: string, reason: string|null}>
 */
final readonly class RawSqlConnectionCallCollector implements Collector
{
    public function __construct(private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer) {}

    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    /**
     * @return array{method: string, line: int, resolved: string, scope: string|null, signal: string, origin: string, reason: string|null}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (! $node->name instanceof Identifier) {
            // A dynamic method name. Nothing here says it is a statement sink, and guessing would
            // collect every dynamic dispatch in the project.
            return null;
        }

        $method = $node->name->toString();

        if (! in_array($method, RawSqlSinks::STATEMENT_SINKS, true)) {
            return null;
        }

        $receiver = $scope->getType($node->var);

        if ($receiver->getObjectClassNames() === []) {
            // Resolved to nothing at all. The NAME is the only evidence left, so only a name no
            // builder shares may speak here — see the class docblock.
            return in_array($method, RawSqlSinks::CONNECTION_ONLY_SINKS, true)
                ? $this->undeterminedReceiver($method, $node->getStartLine(), $receiver, $scope)
                : null;
        }

        if (! $this->isConnection($receiver)) {
            return null;
        }

        $arguments = $node->getArgs();

        $verdict = $arguments === []
            ? null
            : $this->analyzer->classify($arguments[0]->value, $arguments[1]->value ?? null, $scope);

        return [
            'method' => $method,
            'line' => $node->getStartLine(),
            'resolved' => $scope->getType($node)->describe(VerbosityLevel::typeOnly()),
            'signal' => $verdict?->signal->value ?? 'undetermined',
            // Whether the engine's identifier quoting stands between the value and the text.
            // It does not change the signal — see ParameterizationVerdict — it lets the rule
            // downstream name a remedy that exists at a position no engine parameterizes.
            'quoted' => $verdict->identifierQuoted ?? false,
            'origin' => $verdict?->origin->value ?? 'unknown_variable',
            'reason' => $verdict instanceof ParameterizationVerdict
                ? $verdict->reason?->value
                : UndeterminedReason::ArgumentTypeUnresolved->value,
            'scope' => $this->scopeName($scope),
        ];
    }

    /**
     * @return array{method: string, line: int, resolved: string, scope: string|null, signal: string, origin: string, reason: string|null}
     */
    private function undeterminedReceiver(string $method, int $line, Type $receiver, Scope $scope): array
    {
        return [
            'method' => $method,
            'line' => $line,
            // The receiver's own description, not the call's: what could not be read is the thing
            // this row is about, and a reader chasing it needs to see what the analyzer did make of
            // it. `mixed` and `string` are different problems.
            'resolved' => $receiver->describe(VerbosityLevel::typeOnly()),
            'scope' => $this->scopeName($scope),
            'signal' => 'undetermined',
            // Not a claim about the SQL — nothing looked at it.
            'origin' => 'unknown_variable',
            'reason' => UndeterminedReason::ReceiverTypeUnknown->value,
        ];
    }

    /**
     * Is the receiver a database connection?
     *
     * `isSuperTypeOf` rather than a name comparison, and BOTH the contract and the concrete class:
     * `DB::connection()` hands back `Illuminate\Database\Connection`, while a constructor parameter
     * is idiomatically typed `ConnectionInterface`. Listing only one would be silent on the other,
     * which is the shape of defect this class exists to remove.
     */
    private function isConnection(Type $receiver): bool
    {
        return array_any(
            [Connection::class, ConnectionInterface::class],
            fn (string $class): bool => new ObjectType($class)->isSuperTypeOf($receiver)->yes(),
        );
    }

    /**
     * The finest name this call site can be justified under — `Class::method`, the class, or null.
     *
     * The same format the other two collectors record, so a rule joining on scope reads one shape
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
