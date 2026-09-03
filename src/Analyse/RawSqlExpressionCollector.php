<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;

/**
 * `DB::raw()` — the fourth call shape, and the one that was in none of the three lists.
 *
 * ## Why it needs a collector rather than a line in an existing one
 *
 * Two constraints meet here, and together they leave exactly one arrangement.
 *
 * The first is mechanical: PHPStan's registry does not walk node subclasses (measured, see
 * {@see RawSqlFragmentCollector}), so a `StaticCall` needs a collector that declares `StaticCall`.
 * The fluent `$builder->raw(…)` and `$connection->raw(…)` forms are `MethodCall`s and are covered
 * where the rest of the fragment family is.
 *
 * The second decides which EXISTING collector it could not have joined. {@see RawSqlCallCollector}
 * already visits `StaticCall` on the facade — but it is read by the POLICY rule, which asks whether
 * reaching for raw SQL was a deliberate decision and demands a written justification when it was
 * not. `DB::raw('count(*)')` is ordinary Laravel written thousands of times, and requiring a reason
 * for each one is the fastest way to have the analyse suite switched off in an application. So the
 * separation is by COLLECTOR, not by a flag a rule has to remember to check: this data is read by
 * {@see RawInterpolationRule} and by nothing else, and the policy rule cannot reach it by accident.
 *
 * ## What it is looking for
 *
 * `raw()` executes nothing. It wraps text in an `Illuminate\Database\Query\Expression` that the
 * grammar renders verbatim into whatever statement receives it. For the injection question — did a
 * runtime value reach the STATEMENT rather than the parameters — that is precisely a sink, and a
 * sharper one than its siblings: `raw()` has no bindings parameter at all, so there is no
 * parameterized form to fall back on. `DB::raw("… '{$value}'")` is the pattern
 * `SEC.INJ.RAW_INTERPOLATION` exists to find, written in the one place nothing was looking.
 *
 * The row shape is the fragment collector's, so a rule joining across collectors reads one format.
 *
 * @implements Collector<StaticCall, array{method: string, line: int, scope: string|null, signal: string, origin: string, reason: string|null}>
 */
final readonly class RawSqlExpressionCollector implements Collector
{
    private DatabaseFacadeName $facade;

    public function __construct(
        ReflectionProvider $reflection,
        private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer,
    ) {
        $this->facade = new DatabaseFacadeName($reflection);
    }

    public function getNodeType(): string
    {
        return StaticCall::class;
    }

    /**
     * @return array{method: string, line: int, scope: string|null, signal: string, origin: string, reason: string|null}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (! $node->name instanceof Identifier) {
            return null;
        }

        // Read out of the shared vocabulary rather than compared against the literal 'raw', so a
        // second expression producer added to FRAGMENT_SINKS is picked up here without a second
        // edit — and so this collector cannot come to disagree with the list about what counts.
        // The intersection with what is reachable STATICALLY is what `isDatabaseFacade` decides:
        // the builder-only members of the family are simply never written this way.
        if (! in_array($node->name->toString(), RawSqlSinks::FRAGMENT_SINKS, true)) {
            return null;
        }

        if (! $this->facade->isDatabaseFacade($node, $scope)) {
            return null;
        }

        $arguments = $node->getArgs();

        if ($arguments === []) {
            // No argument, no SQL to look at. A runtime error waiting to happen rather than a
            // statement anybody can classify — the same answer the other collectors give.
            return null;
        }

        // Argument 1 is read even though `raw()` has none, and that is deliberate rather than
        // sloppy: the analyzer's contract is (text, bindings|null), and passing null here says "no
        // bindings exist" — which for `raw()` is the permanent truth, not a missing measurement.
        $verdict = $this->analyzer->classify($arguments[0]->value, $arguments[1]->value ?? null, $scope);

        return [
            'method' => $node->name->toString(),
            'line' => $node->getStartLine(),
            'scope' => $this->scopeName($scope),
            'signal' => $verdict->signal->value,
            'origin' => $verdict->origin->value,
            'reason' => $verdict->reason?->value,
        ];
    }

    /**
     * The finest name this call site can be attributed to — `Class::method`, the class, or null.
     *
     * The same shape the other collectors record, so a rule joining on scope reads one format
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
