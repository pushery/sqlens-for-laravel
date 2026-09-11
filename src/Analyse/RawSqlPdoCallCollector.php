<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PDO;
use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Type\ObjectType;
use PHPStan\Type\Type;
use PHPStan\Type\VerbosityLevel;

/**
 * Statement sinks reached on a BARE PDO handle — the form every other collector is blind to.
 *
 * ## What was missing, and how it came to light
 *
 * A consumer moved one statement from `Connection::select()` onto the PDO underneath, because the
 * code runs inside a connector where no Laravel connection exists yet:
 *
 *     $statement = $connection->prepare('select set_config(?, ?, false)');
 *     $statement->execute([$setting, trim($value)]);
 *
 * The suite then reported their `#[RawSql]` reason as STALE — "justifies no raw SQL any more" —
 * because from its point of view the raw SQL had gone. It had not; it had moved one layer down,
 * out of view. The reason went away and the statement stayed, which is the wrong half to lose.
 *
 * That instance is harmless: both values are bound. `$pdo->query("… {$value} …")` is not, and it
 * was equally invisible. And the places people reach for a bare PDO are exactly the places a
 * Laravel connection is not available yet — a connector, a health check, a migration helper — so
 * this is not an exotic corner.
 *
 * ## Why the receiver decides ALONE here, with no name-based fallback
 *
 * {@see RawSqlConnectionCallCollector} has three branches, and its third one lets a NAME speak when
 * the receiver resolves to nothing: `->unprepared()` is written on connections and on nothing else,
 * so the name is evidence by itself.
 *
 * ⚠️ **There is no such branch here, and leaving it out is the design rather than an omission.**
 * `prepare`, `query` and `exec` are among the most ordinary method names in PHP — a repository, a
 * cache, a template engine and an HTTP client may each declare all three. A name-based fallback
 * would put a finding on ordinary code in every project, which is the fastest way to get the whole
 * analyse suite switched off. An unresolved receiver is therefore silence, and the recall that
 * costs is stated rather than hidden: a `$pdo` the analyzer cannot type is a statement this
 * collector does not see.
 *
 * `isSuperTypeOf` rather than a name comparison, for the reason the sibling gives: the driver
 * subclasses (`Pdo\Pgsql`, `Pdo\Mysql`, `Pdo\Sqlite`) are what PHP 8.4 hands back, and matching
 * `PDO` by name alone would be silent on every one of them.
 *
 * ## The bindings arrive at a DIFFERENT call, and it does not matter
 *
 * `prepare()` carries the text and no bindings; `execute()` carries the bindings and no text. That
 * looked like a reason this could not be classified at one call site — and it is not, because the
 * question this suite asks is whether a runtime value reached the TEXT. A value interpolated into
 * the string handed to `prepare()` is already in the statement, and no later `execute()` can take
 * it back out. A literal with `?` placeholders classifies as a literal and draws nothing.
 *
 * So all three names are classified with the text as the first argument and NO bindings argument,
 * which is the truth about the call rather than a simplification of it.
 *
 * @implements Collector<MethodCall, array{method: string, line: int, resolved: string, scope: string|null, signal: string, quoted: bool, origin: string, reason: string|null}>
 */
final readonly class RawSqlPdoCallCollector implements Collector
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

        if (! in_array($method, RawSqlSinks::PDO_STATEMENT_SINKS, true)) {
            return null;
        }

        // The receiver, and nothing else. See the class docblock: there is deliberately no branch
        // here for a receiver that resolves to nothing, because none of these three names is
        // evidence of anything on its own.
        if (! $this->isPdo($scope->getType($node->var))) {
            return null;
        }

        $arguments = $node->getArgs();

        // No bindings argument for any of the three. `prepare()` takes only the statement, and
        // `query()` and `exec()` take only the statement too — PDO's remaining parameters are fetch
        // modes, not values. Passing one would tell the analyzer a value was parameterized when
        // nothing at this call site parameterizes anything.
        $verdict = $arguments === []
            ? null
            : $this->analyzer->classify($arguments[0]->value, null, $scope);

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
            'scope' => $this->scopeName($scope),
        ];
    }

    /**
     * Is the receiver a PDO handle?
     *
     * One class rather than a list, and that is the difference from the connection collector: PHP
     * has exactly one PDO base, and `isSuperTypeOf` carries the driver subclasses with it. There is
     * no second spelling here the way `ConnectionInterface` sits beside `Connection`.
     */
    private function isPdo(Type $receiver): bool
    {
        return new ObjectType(PDO::class)->isSuperTypeOf($receiver)->yes();
    }

    /**
     * The finest name this call site can be justified under — `Class::method`, the class, or null.
     *
     * The same format the other three collectors record, so a rule joining on scope reads one shape
     * whichever collector produced the row. That matters here more than elsewhere: a bare PDO call
     * usually sits in a connector or a health check, and those are ordinary classes that may hold
     * one reasoned raw statement beside code that has nothing to do with SQL.
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
