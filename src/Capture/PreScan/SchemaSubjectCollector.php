<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
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
 * anchor — it is a finding pointed at the WRONG migration, which is worse than one pointed at
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
    private const array TABLE_METHODS = ['create', 'table', 'createIfNotExists'];

    /** @var array<string, array{file: string, line: int}> subject => where it was introduced */
    private array $subjects = [];

    /** The table whose closure the walk is currently inside, or null at the top level. */
    private ?string $insideTable = null;

    public function __construct(private readonly string $file) {}

    public function enterNode(Node $node): null
    {
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
        // Closed on the way out of the same call that opened it. Leaving on the CLOSURE instead
        // would be wrong for a migration that passes no closure at all.
        if ($node instanceof StaticCall && $this->tableNameOf($node) === $this->insideTable && $this->insideTable !== null) {
            $this->insideTable = null;
        }

        return null;
    }

    /**
     * Subject name => the file and line that introduced it.
     *
     * Keys are what a catalog finding is about with the schema stripped: `orders` for the table,
     * `orders.customer_id` for the column. Matching a schema-qualified catalog name onto them is
     * the map's job, not this collector's — a migration never says `public`.
     *
     * @return array<string, array{file: string, line: int}>
     */
    public function subjects(): array
    {
        return $this->subjects;
    }

    private function enterSchemaCall(StaticCall $node): void
    {
        $table = $this->tableNameOf($node);

        if ($table === null) {
            return;
        }

        $this->insideTable = $table;

        // First writer wins. A table created in one migration and altered in three later ones
        // belongs to the first: the map answers where a subject came FROM. The files are walked in
        // name order, which for Laravel's timestamped migrations is chronological order.
        $this->subjects[$table] ??= ['file' => $this->file, 'line' => $node->getStartLine()];
    }

    private function enterColumnCall(MethodCall $node): void
    {
        if (! $node->name instanceof Identifier) {
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
        $this->subjects[$this->insideTable.'.'.$first->value->value] ??= [
            'file' => $this->file,
            'line' => $node->getStartLine(),
        ];
    }

    /** The literal table name a `Schema::` call names, or null when it names anything else. */
    private function tableNameOf(StaticCall $node): ?string
    {
        if (! $node->class instanceof Name || ! $node->name instanceof Identifier) {
            return null;
        }

        // The resolved name, so an aliased or unimported `Schema` is the same subject. The pre-scan's
        // name resolver has already run over this AST.
        $class = $node->class->toString();

        if (! str_ends_with($class, 'Schema')) {
            return null;
        }

        if (! in_array($node->name->toString(), self::TABLE_METHODS, true)) {
            return null;
        }

        $first = $node->args[0] ?? null;

        if (! $first instanceof Arg || ! $first->value instanceof String_) {
            return null;
        }

        return $first->value->value;
    }
}
