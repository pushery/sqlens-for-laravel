<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Illuminate\Database\Eloquent\Builder as EloquentBuilder;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Database\Query\Builder as QueryBuilder;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;
use Pushery\SQLens\Subjects\ParametrizationSignal;

/**
 * Column and direction arguments — the places a value becomes part of the statement's GRAMMAR.
 *
 * ## Why identifiers need their own collector
 *
 * A value can be bound; an identifier cannot. `whereRaw('status = ?', [$status])` keeps the value
 * out of the statement, and there is no equivalent for `orderBy($column)` — the column name IS the
 * statement. So the two families ask different questions and the answers differ in what they can
 * recommend: the raw-SQL rules say "bind it", this one has to say "choose from a list you wrote".
 *
 * ## The classification is done here, and the noise control is free
 *
 * Measured against `laravel/framework` v13.23.0 with Larastan:
 *
 *     $request->input('sort')                            →  mixed
 *     if (in_array($sort, ['name','created_at'], true))  →  'created_at'|'name'
 *     self::SORTABLE[$key] ?? 'created_at'               →  'created_at'|'customer_name'
 *     match ((string) $request->input('sort')) { … }     →  'created_at'|'customer_name'
 *
 * Every allowlist shape a team actually writes narrows to a union of constant strings. So
 * {@see ParameterizationAnalyzer} — the same classifier the raw-SQL rules use — already recognizes
 * them, and this collector needs no allowlist logic of its own. That is the difference between a
 * rule people keep and a rule they switch off in week one: sorting UIs are the single most common
 * thing a Laravel application does.
 *
 * **Two mechanisms keep a guarded call quiet, and they are not the same one.** Written the usual
 * way — read the request into a variable, guard it, pass the variable — the expression reaching
 * `orderBy()` is a bare `$sort`, so {@see RequestOrigin} sees no request and the RULE stays silent;
 * the narrowing is true but is not what suppressed the finding. Written inline, with the request
 * inside the argument, the origin check says yes and only the narrowing is left to do the work.
 *
 * That distinction is not decoration: with only the first shape in the fixture, deleting the
 * classification below changed nothing at all, so the arm asserting the allowlist was asserting
 * something else. The corpus now carries the inline form for exactly that reason.
 *
 * `*Raw` methods are deliberately absent from the list below. `orderByRaw()` is a raw-SQL fragment
 * and belongs to the interpolation rule; collecting it here as well would produce two findings for
 * one call under two ids.
 *
 * @implements Collector<MethodCall, array{method: string, line: int, scope: string|null, signal: string, fromRequest: bool}>
 */
final readonly class DynamicIdentifierCollector implements Collector
{
    /**
     * Builder methods whose FIRST argument is a column name.
     *
     * `latest()` and `oldest()` default to `created_at` and take a column when given one, which is
     * exactly the shape a sortable listing uses. Verified present on `Query\Builder` by
     * `DynamicIdentifierCollectorTest`, for the same reason the raw-SQL sinks are: a remembered
     * method list fails silently.
     *
     * @var list<string>
     */
    public const array IDENTIFIER_METHODS = ['groupBy', 'latest', 'oldest', 'orderBy', 'orderByDesc'];

    public function __construct(
        private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer,
        private RequestOrigin $origin = new RequestOrigin,
    ) {}

    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    /**
     * @return array{method: string, line: int, scope: string|null, signal: string, fromRequest: bool}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        if (! $node->name instanceof Identifier) {
            return null;
        }

        $method = $node->name->toString();

        if (! in_array($method, self::IDENTIFIER_METHODS, true)) {
            return null;
        }

        $arguments = $node->getArgs();

        if ($arguments === []) {
            // `latest()` with no argument sorts by the model's timestamp column. Nothing arrives
            // from outside, so there is nothing to judge.
            return null;
        }

        $receiver = $scope->getType($node->var);

        if ($receiver->getObjectClassNames() === [] || ! $this->isQueryBuilder($receiver)) {
            // Unlike the raw-SQL collector, an unresolved receiver is dropped rather than recorded.
            // There the method name alone is near-conclusive — `whereRaw()` on a non-builder is rare
            // enough to be worth a named `undetermined`. Here the names are ordinary English:
            // `orderBy`, `latest` and `groupBy` appear on collections, repositories and DTOs in
            // every codebase, so recording every unresolved one would bury the real findings.
            return null;
        }

        // The DIRECTION argument is judged with the column: `orderBy($col, $dir)` puts both into the
        // grammar, and a direction taken from the request is the same defect in a smaller place.
        $judged = array_values(array_slice($arguments, 0, 2));

        $verdicts = array_map(
            fn (Arg $argument): ParameterizationVerdict => $this->analyzer->classify($argument->value, null, $scope),
            $judged,
        );

        $constant = array_reduce(
            $verdicts,
            static fn (bool $carry, ParameterizationVerdict $verdict): bool => $carry
                && $verdict->signal === ParametrizationSignal::Parametrized,
            true,
        );

        if ($constant) {
            // Every argument is one of a finite set the author wrote — a hardcoded column, an
            // allowlist guard, a constant map, a match. Nothing to report, and this is the branch
            // that decides whether anybody keeps the rule switched on.
            return null;
        }

        return [
            'method' => $method,
            'line' => $node->getStartLine(),
            'scope' => $this->scopeName($scope),
            'signal' => 'interpolated',
            'fromRequest' => $this->anyFromRequest($judged, $scope),
        ];
    }

    /**
     * @param  list<Arg>  $arguments
     */
    private function anyFromRequest(array $arguments, Scope $scope): bool
    {
        return array_any($arguments, fn (Arg $argument): bool => $this->origin->reaches($argument->value, $scope));
    }

    private function isQueryBuilder(Type $receiver): bool
    {
        return array_any([QueryBuilder::class, EloquentBuilder::class, Relation::class], fn (string $class): bool => new ObjectType($class)->isSuperTypeOf($receiver)->yes());
    }

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
