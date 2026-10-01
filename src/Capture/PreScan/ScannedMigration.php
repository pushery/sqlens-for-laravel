<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Attribute;
use PhpParser\Node\AttributeGroup;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Nop;
use PhpParser\NodeFinder;
use Pushery\SQLens\Attributes\NoSqlOnDriver;
use Pushery\SQLens\Subjects\DownMethodState;

/**
 * One migration file, parsed once, with every call in it already resolved.
 *
 * The file is parsed a SINGLE time and the result is shared by every detector.
 * Parsing per pattern would multiply the pre-scan's cost by the number of
 * detectors, and the pre-scan sits in front of the single-file fast path whose
 * whole promise is a sub-second run — a gate that is felt gets configured away.
 */
final readonly class ScannedMigration
{
    /**
     * The migration methods, where what a capture runs starts. Together with the constructor they
     * are the roots of {@see self::migrationCalls()}; a method none of them reaches exists in the file
     * but does not run as part of a migration, and a detector that judged it would ask users to
     * change something that alters nothing.
     *
     * @var list<string>
     */
    public const array MIGRATION_METHODS = ['up', 'down'];

    /**
     * @param  list<Node>  $ast
     * @param  list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}>  $calls
     */
    public function __construct(
        public string $file,
        public array $ast,
        public array $calls,
    ) {}

    /**
     * What this file's `down()` amounts to: declared with statements, declared but empty, or
     * not declared at all.
     *
     * Read off the AST the pre-scan already parsed, so it costs no second parse — the whole
     * cost model of the pre-scan rests on parsing each file exactly once, and the fast path's
     * sub-second promise rests on that.
     *
     * A file holding several classes is judged by the FIRST one that declares either migration
     * method: a Laravel migration file returns one anonymous class, and a helper class beside
     * it (or a trait) must not be mistaken for the migration itself. A file with no such class
     * reports {@see DownMethodState::Missing} — nothing there can be rolled back either.
     */
    public function downMethodState(): DownMethodState
    {
        $classes = new NodeFinder()->findInstanceOf($this->ast, ClassLike::class);

        foreach ($classes as $class) {
            $down = null;
            $declaresMigrationMethod = false;

            foreach ($class->getMethods() as $method) {
                if (! in_array($method->name->toLowerString(), self::MIGRATION_METHODS, true)) {
                    continue;
                }

                $declaresMigrationMethod = true;

                if ($method->name->toLowerString() === 'down') {
                    $down = $method;
                }
            }

            if (! $declaresMigrationMethod) {
                continue;
            }

            if (! $down instanceof ClassMethod) {
                return DownMethodState::Missing;
            }

            return $this->runsNothing($down) ? DownMethodState::Empty : DownMethodState::Present;
        }

        return DownMethodState::Missing;
    }

    /**
     * The drivers this file DECLARES it deliberately emits nothing on, mapped to the stated reason.
     *
     * Read off the AST the pre-scan already parsed, exactly like {@see DownMethodState()} above, so
     * it costs no second parse — the fast path's sub-second promise rests on parsing each file once.
     *
     * Read from the source, not by reflection, and the reason is the shape of a Laravel
     * migration. Since Laravel 9 a migration file returns an anonymous class, so there is no name to
     * reflect on until the file has been required — and the pre-scan runs before anything is
     * required, on purpose. The AST is the only place the answer exists at this point.
     *
     * A class-level annotation covers both migration methods; a method-level one covers that method.
     * The finer form matters: a migration whose `up()` is deliberately empty on SQLite may still owe
     * a real `down()`, and a class-level annotation would excuse both.
     *
     * An attribute whose reason is an empty string is ignored — a reason nobody wrote is the state
     * this whole mechanism exists to surface, so it must not be the thing that silences it.
     *
     * @param  string  $method  `up` or `down`
     * @return array<string, string> driver name => the stated reason
     */
    public function driversDeclaredEmpty(string $method): array
    {
        $declared = [];

        foreach (new NodeFinder()->findInstanceOf($this->ast, ClassLike::class) as $class) {
            foreach ($this->readNoSqlOnDriver($class->attrGroups) as $driver => $reason) {
                $declared[$driver] = $reason;
            }

            foreach ($class->getMethods() as $classMethod) {
                if ($classMethod->name->toLowerString() !== strtolower($method)) {
                    continue;
                }

                foreach ($this->readNoSqlOnDriver($classMethod->attrGroups) as $driver => $reason) {
                    $declared[$driver] = $reason;
                }
            }
        }

        return $declared;
    }

    /**
     * The `#[NoSqlOnDriver]` annotations in these groups, as driver => reason.
     *
     * Matched on the LAST segment of the attribute name, so it works whether the file imported the
     * class or wrote it fully qualified — the pre-scan resolves names, but a migration is an
     * ordinary file and both spellings are ordinary things to write.
     *
     * Only literal strings are read. A constant or a variable in either argument means evaluating
     * project code to learn what a migration promises, and that is a thing this package does not do
     * — the same decision `#[RawSql]` makes about its own reason.
     *
     * @param  array<AttributeGroup>  $groups
     * @return array<string, string>
     */
    private function readNoSqlOnDriver(array $groups): array
    {
        $found = [];

        foreach ($groups as $group) {
            foreach ($group->attrs as $attribute) {
                if (strtolower($attribute->name->getLast()) !== $this->noSqlOnDriverName()) {
                    continue;
                }

                $driver = $this->literalArgument($attribute, 0, 'driver');
                $reason = $this->literalArgument($attribute, 1, 'reason');

                if ($driver === null || $driver === '' || $reason === null || $reason === '') {
                    continue;
                }

                $found[$driver] = $reason;
            }
        }

        return $found;
    }

    /**
     * The short name of {@see NoSqlOnDriver}, lowercased — read OFF THE CLASS, never typed.
     *
     * A literal here would leave the attribute class with no reference anywhere in `src/`, which is
     * what the unwired-mechanism guard reports and is right to: a class nothing names is a class a
     * rename silently detaches from the reader looking for it. Deriving it means a rename either
     * carries this along or does not compile.
     *
     * A constant cannot hold this — `const` takes no function call — so it is a method.
     */
    private function noSqlOnDriverName(): string
    {
        $segments = explode('\\', NoSqlOnDriver::class);

        return strtolower(end($segments));
    }

    /**
     * One argument of an attribute, by position OR by name, when it is a plain string literal.
     *
     * Both forms are read because both are written: `#[NoSqlOnDriver('sqlite', reason: '…')]` mixes
     * them in the very example the attribute's own docblock gives. A named argument may also appear
     * in any order, so position alone would miss it.
     */
    private function literalArgument(Attribute $attribute, int $position, string $name): ?string
    {
        foreach ($attribute->args as $index => $argument) {
            $matchesName = $argument->name?->toString() === $name;
            $matchesPosition = $argument->name === null && $index === $position;

            if (! $matchesName && ! $matchesPosition) {
                continue;
            }

            return $argument->value instanceof String_ ? $argument->value->value : null;
        }

        return null;
    }

    /**
     * Whether a method body executes nothing at all.
     *
     * `Nop` nodes are dropped, and that is the whole subtlety: the parser materializes a
     * standalone comment as a statement, so `down() { // nothing to undo }` arrives with a
     * statement count of one and would read as a working rollback. A comment saying there is
     * nothing to undo is exactly the body this rule is looking for.
     *
     * An abstract or interface method has a null body — nothing to run either way.
     */
    private function runsNothing(ClassMethod $method): bool
    {
        $statements = array_filter(
            $method->stmts ?? [],
            static fn (Node $statement): bool => ! $statement instanceof Nop,
        );

        return $statements === [];
    }

    /**
     * Every call the file makes, with its resolved target, line, scope and
     * control-flow context.
     *
     * @return list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}>
     */
    public function calls(): array
    {
        return $this->calls;
    }

    /**
     * The calls a capture runs, which is what detectors read.
     *
     * Loading the file runs its top-level code, instantiating the migration runs its constructor, and
     * `up()` or `down()` runs every method and function it reaches. So a call counts when it stands
     * at the top level or in a function-like of {@see self::reachableScopes()}.
     *
     * @return list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}>
     */
    public function migrationCalls(): array
    {
        $reachable = $this->reachableScopes();

        return array_values(array_filter(
            $this->calls,
            static fn (array $call): bool => $call['scope'] === null || $reachable === null || in_array($call['scope'], $reachable, true),
        ));
    }

    /**
     * The named function-likes a capture runs.
     *
     * The migration methods and the constructor run by construction. Each of them runs what it calls
     * of its own class through `$this->m()`, `self::m()` or `static::m()`, the functions of the file
     * it calls by name, and a method it hands over as `[$this, 'm']`, and those run theirs in turn.
     * The top-level code of the file is a root as well.
     *
     * Null when one of them calls a method of its own class by a name only known at run time: any of
     * them may run then, so all of them are read.
     *
     * @return list<string>|null
     */
    private function reachableScopes(): ?array
    {
        $reachable = [...self::MIGRATION_METHODS, '__construct', ...$this->callableReferences()];

        for ($grown = true; $grown;) {
            $grown = false;

            foreach ($this->calls as $call) {
                if ($call['scope'] !== null && ! in_array($call['scope'], $reachable, true)) {
                    continue;
                }

                if ($this->callsOwnMethodDynamically($call['node'])) {
                    return null;
                }

                $callee = $this->ownCallee($call['node']);

                if ($callee !== null && ! in_array($callee, $reachable, true)) {
                    $reachable[] = $callee;
                    $grown = true;
                }
            }
        }

        return $reachable;
    }

    /**
     * The name a call reaches inside this file: a method of the class on `$this`, `self` or
     * `static`, or a function called by name. Null for anything else.
     */
    private function ownCallee(Node $node): ?string
    {
        if ($node instanceof MethodCall && $this->isThis($node->var) && $node->name instanceof Identifier) {
            return $node->name->toString();
        }

        if ($node instanceof StaticCall && $this->isOwnClass($node->class) && $node->name instanceof Identifier) {
            return $node->name->toString();
        }

        return $node instanceof FuncCall && $node->name instanceof Name ? $node->name->getLast() : null;
    }

    /** Whether a call reaches a method of its own class by a name only known at run time. */
    private function callsOwnMethodDynamically(Node $node): bool
    {
        if ($node instanceof MethodCall && $this->isThis($node->var)) {
            return ! $node->name instanceof Identifier;
        }

        return $node instanceof StaticCall && $this->isOwnClass($node->class) && ! $node->name instanceof Identifier;
    }

    /**
     * The methods the file hands over as `[$this, 'm']`, to `array_map()`, `call_user_func()` or
     * `Closure::fromCallable()`. Such a reference is no call node, and the method it names runs all
     * the same. Read over the whole file rather than per function-like, which can only add a method.
     *
     * @return list<string>
     */
    private function callableReferences(): array
    {
        $names = [];

        foreach (new NodeFinder()->findInstanceOf($this->ast, Array_::class) as $array) {
            $items = $array->items;

            if (count($items) === 2 && $this->isThis($items[0]->value) && $items[1]->value instanceof String_) {
                $names[] = $items[1]->value->value;
            }
        }

        return $names;
    }

    private function isThis(Node $node): bool
    {
        return $node instanceof Variable && $node->name === 'this';
    }

    private function isOwnClass(Node $class): bool
    {
        return $class instanceof Name && in_array($class->toLowerString(), ['self', 'static'], true);
    }

    /**
     * The calls whose target the scanner could not resolve. A detector that
     * cares about a specific surface still has to account for these — an
     * unresolved call may BE that surface, reached dynamically.
     *
     * @return list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}>
     */
    public function dynamicCalls(): array
    {
        return array_values(array_filter(
            $this->calls,
            static fn (array $call): bool => $call['target']->isDynamic,
        ));
    }
}
