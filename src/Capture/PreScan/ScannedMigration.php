<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Stmt\ClassLike;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Nop;
use PhpParser\NodeFinder;
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
     * The migration methods a pre-scan judges. Code outside them exists in the
     * file but does not run as part of a migration, and a detector that judged it
     * would ask users to change something that alters nothing.
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
     * The calls that run as part of `up()` or `down()`, which is the only code a
     * capture ever executes. This is what detectors read.
     *
     * @return list<array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}>
     */
    public function migrationCalls(): array
    {
        return array_values(array_filter(
            $this->calls,
            static fn (array $call): bool => in_array($call['scope'], self::MIGRATION_METHODS, true),
        ));
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
