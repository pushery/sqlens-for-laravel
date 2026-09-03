<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Collectors\Collector;
use PHPStan\Reflection\ReflectionProvider;
use PHPStan\Type\VerbosityLevel;

/**
 * Every `DB::…()` call site that hands SQL to the database, collected from the whole codebase.
 *
 * This is the producer the analyse suite was missing. `RawSql` has existed as a subject for a long
 * time and nothing in the package ever constructed one, so every rule written against it was
 * unreachable in a real run — green in every test, silent in every project.
 *
 * ## Why a PHPStan collector and not the pre-scan that already exists
 *
 * `src/Capture/PreScan/` already recognizes call sites, resolves names and separates direct calls
 * from indirect ones — and none of that is duplicated here, deliberately: a second call-site
 * vocabulary is exactly the kind of double ownership this package forbids. What the pre-scan cannot
 * do is REACH. Its entry point is `MigrationFileScanner`, so it reads migrations; the injection
 * rules ask about raw SQL anywhere in application code. PHPStan is used for the traversal, not for
 * the recognition.
 *
 * ## What was measured before this file existed
 *
 * The one question that decides this design: does `DB::statement(...)` resolve to a type, or must
 * SQLens carry its own facade resolution?
 *
 * It is answered, pinned, and NOT by this file. `tests/Feature/Analyse/PhpStanExtensionApiTest` runs
 * a real analyse against a real fixture project and asserts the result:
 *
 *     DB::connection('pgsql')->statement(…)   subject type  →  Illuminate\Database\Connection
 *     DB::statement(…)                        return type   →  bool   (= Connection::statement())
 *     DB::select(…)                           return type   →  array  (= Connection::select())
 *
 * So **Larastan routes the facade**; an unrouted call would come back `mixed`. That is what keeps
 * this collector small — no name resolution of its own to drift with every Laravel release — and it
 * is also why the two call shapes need different questions: the object form is identified by the
 * type of its SUBJECT, the facade form only by the type of the CALL, because a static call's subject
 * is a class name and asking what type that name has answers "the facade", which is true and useless.
 *
 * Neither `Connection::statement()` nor `Connection::select()` declares a PHP return type, so those
 * types come from Larastan's own knowledge rather than from reflection — which is why the question
 * had to be settled through a real analyse instead of read off the class.
 *
 * @implements Collector<StaticCall, array{method: string, line: int, resolved: string, scope: string|null, signal: string, origin: string, reason: string|null}>
 *
 * The type is therefore a CONFIRMATION here, not the identification — the method name says which
 * call this is, and the resolved type says whether the analyzer understood it. Both are collected,
 * because a call the analyzer did not understand is a different fact from one it did, and the rules
 * downstream owe an honest `undetermined` for the first rather than a guess.
 */
final readonly class RawSqlCallCollector implements Collector
{
    /**
     * Recognizing the facade is {@see DatabaseFacadeName}'s job, not this class's.
     *
     * It moved out when `DB::raw()` got a collector of its own: the same question then had two
     * askers, and a copied answer would drift silently in both directions — narrower stops
     * reporting real raw SQL, wider reports a project's own `DB` class.
     */
    private DatabaseFacadeName $facade;

    /**
     * The classifier is a collaborator rather than something the rules apply afterwards, and the
     * reason is structural: it needs a PHPStan `Scope`, and a rule reading a `CollectedDataNode`
     * has none. Classification therefore has to happen while the node is still being visited, which
     * is here.
     */
    public function __construct(
        /**
         * PHPStan's own reflection, and the reason it is a dependency rather than a static call:
         * it is what answers whether a name that is NOT the facade's is nonetheless an alias OF it
         * — the shape `\DB::statement(…)` takes in a normal Laravel application.
         *
         * Taken here rather than a ready-made {@see DatabaseFacadeName} so the constructor keeps the
         * shape PHPStan's own service wiring and every test call site already pass.
         */
        ReflectionProvider $reflection,
        private ParameterizationAnalyzer $analyzer = new ParameterizationAnalyzer,
    ) {
        $this->facade = new DatabaseFacadeName($reflection);
    }

    /**
     * The concrete node class, and that is a measurement rather than a style choice.
     *
     * Returning the base `Node\Expr` collects nothing extra — PHPStan's registry does not walk
     * subclasses, so one collector per node shape is the only way to see more than one. This one
     * covers the static facade form; the fluent `->whereRaw()` form is a MethodCall and needs its
     * own collector, which is a separate piece of work rather than an oversight.
     */
    public function getNodeType(): string
    {
        return StaticCall::class;
    }

    /**
     * @return array{method: string, line: int, resolved: string, scope: string|null, signal: string, origin: string, reason: string|null}|null
     */
    public function processNode(Node $node, Scope $scope): ?array
    {
        // No `instanceof StaticCall` here: the generic annotation above already tells PHPStan the
        // node type, and re-checking it is a branch no run can enter — which the analyzer reports
        // rather than tolerates.
        if (! $node->name instanceof Identifier) {
            return null;
        }

        $method = $node->name->toString();

        // The list lives in RawSqlSinks and is verified against the INSTALLED framework, because a
        // remembered method list fails in the silent direction: five statement sinks were missing
        // from the first version of this collector, so `DB::scalar('SELECT …')` handed raw SQL to
        // the database and produced no finding at all.
        //
        // Only the STATEMENT sinks, deliberately. A fragment sink such as `whereRaw()` is ordinary
        // Laravel, and demanding a written reason for each one is how a suite gets switched off in
        // its first week; the injection rules read those, where the question is whether a runtime
        // value reached the text rather than whether somebody decided.
        //
        // `unprepared` is not special-cased here even though it is the one that matters most:
        // classifying it is the rules' job, and a collector that filtered would decide a question it
        // is not allowed to answer. Collect everything, judge later.
        if (! in_array($method, RawSqlSinks::STATEMENT_SINKS, true)) {
            return null;
        }

        // The type of the SUBJECT, not of the call — and this is the check that says "this really
        // is the DB facade" rather than any class that happens to have a method called `select`.
        // A collector matching on the bare method name would collect every repository, every
        // query builder and every collection in the codebase.
        if (! $this->facade->isDatabaseFacade($node, $scope)) {
            return null;
        }

        // The resolved type, recorded as its description rather than as a verdict about it.
        //
        // There was a boolean here — `understood`, meant to say whether the analyzer resolved the
        // call — and it is gone for two reasons that only showed up together. It compared against
        // an ObjectType named 'mixed', and `mixed` is not a class, so it could never be false: it
        // said "understood" for every call including the ones nobody understood. And it was
        // redundant even when correct, because an unresolved call describes itself as `mixed` right
        // here in `resolved`. A flag that always says yes and duplicates the field beside it is
        // worse than no flag: a rule reading it would gate on something that never varies.
        //
        // A caller that needs the distinction asks `$call['resolved'] === 'mixed'`, which is the
        // same question against data that is actually measured. The gate's Rector step is what
        // surfaced this, as a string class name; the defect underneath was the wrong type.
        $resolved = $scope->getType($node);

        $arguments = $node->getArgs();
        $verdict = $arguments === []
            ? null
            : $this->analyzer->classify($arguments[0]->value, $arguments[1]->value ?? null, $scope);

        return [
            'method' => $method,
            'line' => $node->getStartLine(),
            'resolved' => $resolved->describe(VerbosityLevel::typeOnly()),
            // How the statement's text was assembled, carried beside the call rather than left for a
            // rule to work out later: a rule reads collected DATA and has no scope, so nothing
            // downstream could ask this question again.
            //
            // A call with no arguments at all is `undetermined` rather than absent. It is a runtime
            // error waiting to happen, not a statement anybody can classify, and the honest answer
            // to "what does this SQL look like" is that there is none to look at.
            'signal' => $verdict?->signal->value ?? 'undetermined',
            'origin' => $verdict?->origin->value ?? 'unknown_variable',
            'reason' => $verdict instanceof ParameterizationVerdict
                ? $verdict->reason?->value
                : UndeterminedReason::ArgumentTypeUnresolved->value,
            // WHERE the call sits, as the finest name that can carry a justification: the method
            // if there is one, otherwise the class. Null for a call in a plain function or at file
            // scope — a real shape, not an error, and one that cannot carry a class attribute.
            //
            // The method matters. `#[RawSql]` targets methods as well as classes precisely because a
            // class with one reasoned raw statement and one careless one is an ordinary shape, and
            // recording only the class would excuse both — the careless one silently.
            'scope' => $this->scopeName($scope),
        ];
    }

    /**
     * The finest name this call site can be justified under.
     *
     * `Class::method` where there is a method, the class where the call sits in a class but outside
     * one, and null outside a class entirely. The rule joins on this string, so a class-level
     * annotation has to be checked separately — which it is, because the collector on the other side
     * records both names.
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
