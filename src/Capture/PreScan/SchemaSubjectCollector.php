<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\NodeVisitorAbstract;

/**
 * The catalog subjects a migration introduces, and the line each was introduced on.
 *
 * ## It reads, it does not run — and it refuses to guess
 *
 * The same rule the pre-scan is built on: a migration is parsed, never included. What this adds is
 * that it also refuses to INFER. A table name is taken only from a literal string in the call:
 *
 * ```php
 * Schema::create('orders', ...);          // orders, at this line
 * Schema::create($this->table, ...);      // nothing — and that is the answer
 * Schema::create(self::TABLE, ...);       // nothing, for the same reason
 * ```
 *
 * A constant could be resolved by reading the class, and a property by reading the constructor, and
 * each of those is one more place to be wrong about. The cost of guessing here is not a missing
 * anchor — it is a finding pointed at the wrong migration, which is worse than one pointed at
 * nothing: a reader who follows it edits a file that had nothing to do with it.
 *
 * ## Columns are keyed under their table, because that is how the catalog names them
 *
 * A catalog finding is about `public.orders.customer_id`, so the map has to answer for that, not
 * only for the table. Inside a `Schema::create`/`Schema::table` closure, every `$table->x('name')`
 * contributes `orders.name` — again only where the name is a literal.
 *
 * The closure's table is tracked by nesting, not by variable name. `$table` is a convention, not
 * a rule, and a migration that calls it `$t` is ordinary. The visitor remembers which create/table
 * call it is currently inside, so the receiver's name never matters.
 *
 * ## A drop forgets, and only the drop `up()` makes
 *
 * A table dropped and created again is the second table, and a column dropped and added again is
 * the second column: anchoring either to the first migration would send a reader to a line that
 * describes something the database no longer has. So `Schema::drop()`, `Schema::dropIfExists()` and
 * a builder's `drop…()` in `up()` are reported as drops, in source order beside the introductions,
 * and the map forgets what they name. `down()` reverses `up()` and is read for neither: its drop is
 * the undoing of a create, and its create the undoing of a drop.
 */
final class SchemaSubjectCollector extends NodeVisitorAbstract
{
    /**
     * The `Schema::` methods that name a table in their first argument.
     *
     * `rename` is deliberately absent: its first argument is the old name, so recording it would
     * anchor a subject to the migration that stopped calling it that. The new name is the second
     * argument and could be read — but a rename is not an introduction, and this map answers "where
     * did this come from", not "where was it last touched".
     */
    private const array TABLE_METHODS = ['create', 'table', 'createifnotexists'];

    /** The `Schema::` methods that drop the table named in their first argument. */
    private const array DROP_METHODS = ['drop', 'dropifexists'];

    /**
     * What this migration does to each subject, in source order: an introduction with its line, or
     * a drop, which names a table (and with it its columns) or a single subject under a table.
     *
     * @var list<array{subject: string, file: string, line: int}|array{dropped: string, table: bool}>
     */
    private array $events = [];

    /** The table whose closure the walk is currently inside, or null at the top level. */
    private ?string $insideTable = null;

    /** The lower-cased name of the method the walk is inside, or null outside every method. */
    private ?string $method = null;

    public function __construct(private readonly string $file) {}

    public function enterNode(Node $node): null
    {
        if ($node instanceof ClassMethod) {
            $this->method = $node->name->toLowerString();

            return null;
        }

        if ($node instanceof StaticCall) {
            $this->enterSchemaCall($node);

            return null;
        }

        if ($node instanceof MethodCall && $this->insideTable !== null) {
            $this->enterColumnCall($node);
        }

        return null;
    }

    public function leaveNode(Node $node): null
    {
        if ($node instanceof ClassMethod) {
            $this->method = null;

            return null;
        }

        // Closed on the way out of the same call that opened it. Leaving on the CLOSURE instead
        // would be wrong for a migration that passes no closure at all.
        if ($node instanceof StaticCall && $this->tableNameOf($node) === $this->insideTable && $this->insideTable !== null) {
            $this->insideTable = null;
        }

        return null;
    }

    /**
     * What this migration does to each subject, in source order.
     *
     * Subjects are what a catalog finding is about with the schema stripped: `orders` for the table,
     * `orders.customer_id` for the column. Matching a schema-qualified catalog name onto them is the
     * map's job, not this collector's — a migration never says `public`. A table appears once for
     * every call that names it, and the map keeps the first: a table created in one migration and
     * altered in three later ones belongs to the first, the one it came from.
     *
     * @return list<array{subject: string, file: string, line: int}|array{dropped: string, table: bool}>
     */
    public function events(): array
    {
        return $this->events;
    }

    private function enterSchemaCall(StaticCall $node): void
    {
        $dropped = $this->literalFirstArgument($node, self::DROP_METHODS);

        if ($dropped !== null) {
            if ($this->method === 'up') {
                $this->events[] = ['dropped' => $dropped, 'table' => true];
            }

            return;
        }

        $table = $this->tableNameOf($node);

        if ($table === null) {
            return;
        }

        $this->insideTable = $table;
        $this->introduce($table, $node->getStartLine());
    }

    private function enterColumnCall(MethodCall $node): void
    {
        if (! $node->name instanceof Identifier) {
            return;
        }

        $method = $node->name->toLowerString();

        // A drop names what goes away, never what arrives, so it introduces nothing. `dropColumn`
        // takes column names, one by one or as a list; every other drop names its index or
        // constraint by a string, and a list there holds the COLUMNS Laravel derives that name from,
        // which are not dropped.
        if (str_starts_with($method, 'drop')) {
            if ($this->method === 'up') {
                foreach ($method === 'dropcolumn' ? $this->literalNames($node->args) : $this->literalNames(array_slice($node->args, 0, 1), lists: false) as $name) {
                    $this->events[] = ['dropped' => $this->insideTable.'.'.$name, 'table' => false];
                }
            }

            return;
        }

        $first = $node->args[0] ?? null;

        if (! $first instanceof Arg || ! $first->value instanceof String_) {
            return;
        }

        // Every builder method whose first argument is a literal string names something the catalog
        // can carry: a column, an index, a constraint. Which kind it is does not matter here — the
        // map is asked about a NAME, and a name that turns out to belong to nothing is simply never
        // looked up.
        $this->introduce($this->insideTable.'.'.$first->value->value, $node->getStartLine());
    }

    /**
     * Record an introduction, unless the walk is inside `down()`.
     *
     * `down()` reverses `up()`: a create there brings back what `up()` dropped, and anchoring to it
     * would point a finding at the migration after which the subject no longer exists.
     */
    private function introduce(string $subject, int $line): void
    {
        if ($this->method === 'down') {
            return;
        }

        $this->events[] = ['subject' => $subject, 'file' => $this->file, 'line' => $line];
    }

    /**
     * The literal strings among these arguments, and with `$lists` the literal strings of a list
     * literal among them. Anything else, a variable or a constant, names nothing.
     *
     * @param  array<array-key, mixed>  $args
     * @return list<string>
     */
    private function literalNames(array $args, bool $lists = true): array
    {
        $names = [];

        foreach ($args as $arg) {
            $value = $arg instanceof Arg ? $arg->value : null;

            if ($value instanceof String_) {
                $names[] = $value->value;
            } elseif ($lists && $value instanceof Array_) {
                foreach ($value->items as $item) {
                    if ($item->value instanceof String_) {
                        $names[] = $item->value->value;
                    }
                }
            }
        }

        return $names;
    }

    /** The literal table name a `Schema::` call names, or null when it names anything else. */
    private function tableNameOf(StaticCall $node): ?string
    {
        return $this->literalFirstArgument($node, self::TABLE_METHODS);
    }

    /**
     * The literal first argument of a `Schema::` call to one of these methods, or null.
     *
     * @param  list<string>  $methods  lower-cased method names
     */
    private function literalFirstArgument(StaticCall $node, array $methods): ?string
    {
        if (! $node->class instanceof Name || ! $node->name instanceof Identifier) {
            return null;
        }

        // The resolved name, so an aliased or unimported `Schema` is the same subject. The pre-scan's
        // name resolver has already run over this AST.
        $class = $node->class->toString();

        // Both without regard to case, which is how PHP reads a class and a method name.
        if (! str_ends_with(strtolower($class), 'schema')) {
            return null;
        }

        if (! in_array($node->name->toLowerString(), $methods, true)) {
            return null;
        }

        $first = $node->args[0] ?? null;

        if (! $first instanceof Arg || ! $first->value instanceof String_) {
            return null;
        }

        return $first->value->value;
    }
}
