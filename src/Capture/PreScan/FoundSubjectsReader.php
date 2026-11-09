<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\ArrayItem;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\CallLike;
use PhpParser\Node\Expr\Throw_;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Stmt\Function_;
use PhpParser\NodeFinder;
use Pushery\SQLens\Capture\PreScan\Catalog\CatalogEntry;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalog;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalogs;
use Pushery\SQLens\Subjects\FoundSubjects;

/**
 * Reads {@see FoundSubjects} off a parsed migration: the tables and columns `up()` asks about in a
 * guard, and whether `down()` can throw.
 *
 * A question counts where it decides a branch, the reading {@see SchemaIntrospectionGuardDetector}
 * makes, so a guard whose answer reaches the branch through a variable or a helper's return counts
 * as well. It counts for `up()` where it stands in a method `up()` runs. And it names only what the
 * call names with a literal: `Schema::hasTable($this->table)` asks about a table the parse cannot
 * name, and a guessed name would point a finding at the wrong one.
 */
final readonly class FoundSubjectsReader
{
    private PreScanCatalog $guards;

    public function __construct(?PreScanCatalogs $catalogs = null)
    {
        $this->guards = ($catalogs ?? PreScanCatalogs::bundled())->catalog(PreScanCatalogs::INTROSPECTION_GUARDS);
    }

    /**
     * What the file says, or null where the methods `up()` and `down()` run cannot be told apart,
     * because one of them calls a method of its own class by a name known only at run time.
     */
    public function read(ScannedMigration $migration): ?FoundSubjects
    {
        $up = $migration->scopesReachedFrom('up');
        $down = $migration->scopesReachedFrom('down');

        if ($up === null || $down === null) {
            return null;
        }

        $asked = [];

        foreach ($migration->calls() as $call) {
            if (! $call['context']->insideCondition || ! in_array($call['scope'], $up, true)) {
                continue;
            }

            $entry = $this->guards->match($call['target']);

            if ($entry instanceof CatalogEntry) {
                array_push($asked, ...$this->subjectsOf($call['node'], $entry->kind));
            }
        }

        $asked = array_values(array_unique($asked));
        sort($asked, SORT_STRING);

        return new FoundSubjects($asked, $this->canThrow($migration, $down));
    }

    /**
     * The table a table guard asks about, or the columns a column guard asks about as
     * `table.column`, where the call names them with literals. Nothing for any other guard: an
     * index or the shape of a column holds no rows a rollback could take.
     *
     * @return list<string>
     */
    private function subjectsOf(Node $call, string $kind): array
    {
        $arguments = $call instanceof CallLike && ! $call->isFirstClassCallable() ? $call->getArgs() : [];
        $table = $this->literalsAt($arguments, 0)[0] ?? null;

        if ($table === null) {
            return [];
        }

        return match ($kind) {
            'table_guard' => [$table],
            'column_guard' => array_map(static fn (string $column): string => $table.'.'.$column, $this->literalsAt($arguments, 1)),
            default => [],
        };
    }

    /**
     * The names the argument at this position gives, or none where the call has no such argument.
     *
     * @param  array<Arg>  $arguments
     * @return list<string>
     */
    private function literalsAt(array $arguments, int $position): array
    {
        $argument = $arguments[$position] ?? null;

        return $argument instanceof Arg ? $this->literals($argument->value) : [];
    }

    /**
     * The names a literal string or an array of literal strings gives, lower-cased.
     *
     * @return list<string>
     */
    private function literals(Node $value): array
    {
        $values = $value instanceof Array_
            ? array_map(static fn (?ArrayItem $item): ?Node => $item?->value, $value->items)
            : [$value];

        $names = [];

        foreach ($values as $node) {
            if ($node instanceof String_ && $node->value !== '') {
                $names[] = strtolower($node->value);
            }
        }

        return $names;
    }

    /**
     * Whether one of these function-likes holds a `throw`.
     *
     * @param  list<string>  $scopes
     */
    private function canThrow(ScannedMigration $migration, array $scopes): bool
    {
        $finder = new NodeFinder;

        $functions = $finder->find(
            $migration->ast,
            static fn (Node $node): bool => ($node instanceof ClassMethod || $node instanceof Function_) && in_array($node->name->toString(), $scopes, true),
        );

        return $finder->findFirstInstanceOf($functions, Throw_::class) instanceof Throw_;
    }
}
