<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Drivers\DriverManager;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * Suggests the index a query pattern would use, from the catalog of the connection it ran on.
 *
 * The columns come in the order a b-tree serves them: the ones the pattern compares with a value, then
 * the one it bounds, or the ones it sorts by where it bounds none or bounds the first of them. On
 * PostgreSQL the columns it asks to be null or not make the index a partial one; on MySQL, which has no
 * partial index, a column asked to be null is compared like a value. An index on the table that leads
 * with those columns already serves the pattern. A suggested index names every index it leads with,
 * because RedundantIndex reports such a left prefix once the longer index exists.
 *
 * It only reads: the catalog, through the sealed session every SQLens read takes. It runs no `EXPLAIN`,
 * because a masked pattern has no values to plan with.
 */
final readonly class IndexAdvisor
{
    public function __construct(
        private DriverManager $drivers,
        private CatalogReaderFactory $readers,
        private ReaderConnectionFactory $connections,
        private Repository $config,
    ) {}

    /** The index advice for a pattern that ran on the named connection. */
    public function advise(QueryPattern $pattern, string $connection): IndexAdvice
    {
        $shape = $pattern->coarse
            ? 'the pattern was masked without a grammar for its engine, so where a value ends in it is a guess'
            : PatternShapes::read($pattern->sql);
        $driver = $this->drivers->resolve($connection);

        if (is_string($shape)) {
            return IndexAdvice::undetermined($shape);
        }

        if (! $driver instanceof WritesIndexStatements || ! in_array($driver->key(), ['pgsql', 'mysql'], true)) {
            return IndexAdvice::undetermined('SQLens reads the catalog of PostgreSQL and MySQL, and the connection is neither');
        }

        try {
            $table = $this->tableIn($this->catalogOf($connection, $driver->key()), $shape);
        } catch (Throwable $failure) {
            return IndexAdvice::undetermined('the catalog of the connection could not be read: '.$failure::class);
        }

        return $table instanceof SchemaObject
            ? self::decide($shape, $driver, $table->qualifiedName, $this->membersOf($table))
            : IndexAdvice::undetermined("the catalog holds no table {$shape->table}");
    }

    /**
     * The advice for a shape on a table whose members are known already, without reading a catalog.
     *
     * @param  array{columns: list<string>, indexes: array<string, list<string>>, protected: list<string>, invisible: list<string>}  $members
     */
    public static function decide(PatternShape $shape, WritesIndexStatements $driver, string $table, array $members): IndexAdvice
    {
        $engine = $driver->key();
        $missing = array_values(array_diff($shape->columns(), $members['columns']));

        if ($missing !== []) {
            return IndexAdvice::undetermined($table.' has no column '.implode(', ', $missing));
        }

        $equality = array_values(array_unique([...$shape->equality, ...($engine === 'mysql' ? array_keys(array_filter($shape->nulls)) : [])]));
        $range = array_values(array_diff($shape->range, $equality))[0] ?? null;
        $sort = array_values(array_diff($shape->sort, $equality));
        $tail = $range === null ? $sort : (($sort[0] ?? null) === $range ? $sort : [$range]);
        $columns = array_values(array_unique([...$equality, ...$tail]));
        $predicate = $engine === 'pgsql' ? array_diff_key($shape->nulls, array_flip($columns)) : [];

        if ($columns === []) {
            return IndexAdvice::undetermined('the pattern leaves no column for an index on '.$table.' to lead with');
        }

        $usable = array_diff_key($members['indexes'], array_flip($members['invisible']));

        foreach ($usable as $name => $index) {
            if (self::serves($index, $columns, count($equality))) {
                return IndexAdvice::covered($name, $columns, 'served by '.$name.', which leads with '.implode(', ', $columns));
            }
        }

        $supersedes = $predicate !== [] ? [] : array_map(strval(...), array_keys(array_filter(
            array_diff_key($usable, array_flip($members['protected'])),
            static fn (array $index): bool => count($index) < count($columns) && array_slice($columns, 0, count($index)) === $index,
        )));
        $quote = static fn (string $name): string => $engine === 'pgsql' ? '"'.str_replace('"', '""', $name).'"' : '`'.str_replace('`', '``', $name).'`';
        $conditions = array_map(static fn (string $column, bool $null): string => $quote($column).($null ? ' IS NULL' : ' IS NOT NULL'), array_keys($predicate), $predicate);
        $dot = strpos($table, '.');
        $short = $dot === false ? $table : substr($table, $dot + 1);
        $target = ($dot === false ? '' : $quote(substr($table, 0, $dot)).'.').$quote($short);
        $name = self::nameFor($short, $columns, $engine === 'pgsql' ? 63 : 64);

        $reason = implode('; ', array_filter([
            $equality === [] ? null : 'the pattern compares '.implode(', ', $equality).' with a value',
            $range === null ? null : 'it bounds '.$range,
            $tail === $sort && $sort !== [] ? 'it sorts by '.implode(', ', $sort) : null,
            $conditions === [] ? null : 'it reads only the rows where '.implode(' and ', $conditions),
            $supersedes === [] ? null : 'the index leads with the columns of '.implode(', ', $supersedes).', which it makes redundant',
        ], is_string(...)));

        return IndexAdvice::suggested(
            $driver->indexStatement($target, $quote($name), array_map($quote, $columns), $conditions),
            $columns,
            $supersedes,
            $reason,
        );
    }

    /**
     * Whether an index serves the columns: the compared ones first in any order, then the others in theirs.
     *
     * @param  list<string>  $index
     * @param  list<string>  $columns
     */
    private static function serves(array $index, array $columns, int $compared): bool
    {
        $lead = array_slice($index, 0, $compared);
        $wanted = array_slice($columns, 0, $compared);
        sort($lead);
        sort($wanted);

        return count($index) >= count($columns)
            && $lead === $wanted
            && array_slice($index, $compared, count($columns) - $compared) === array_slice($columns, $compared);
    }

    /**
     * Laravel's name for the index, `table_column_column_index`, cut to the length the engine allows with
     * a hash of the whole name at its end.
     *
     * @param  list<string>  $columns
     */
    private static function nameFor(string $table, array $columns, int $limit): string
    {
        $name = strtolower((string) preg_replace('/[^A-Za-z0-9_]+/', '_', implode('_', [$table, ...$columns, 'index'])));

        return strlen($name) > $limit ? rtrim(substr($name, 0, $limit - 9), '_').'_'.substr(hash('sha256', $name), 0, 8) : $name;
    }

    /**
     * The catalog of the connection, whose reader attaches the columns and indexes of each table.
     *
     * @return list<SchemaObject>
     */
    private function catalogOf(string $connection, string $engine): array
    {
        $profile = $this->config->get('sqlens.profile');
        $context = new SubjectContext(driver: $engine, profile: is_string($profile) ? $profile : 'local', strictTools: false);
        $request = CatalogRequest::fromConfig(
            $this->config,
            types: [SchemaObjectType::Table, SchemaObjectType::Column, SchemaObjectType::Index],
            connection: $connection,
        );

        return $this->readers
            ->for($engine, $this->connections->forConnection($connection), $this->connections->budget(), $context)
            ->catalog
            ->read($request)
            ->objects;
    }

    /**
     * The table the shape reads: by its schema and name where the pattern qualifies it, otherwise by name.
     *
     * @param  list<SchemaObject>  $objects
     */
    private function tableIn(array $objects, PatternShape $shape): ?SchemaObject
    {
        return array_find($objects, static fn (SchemaObject $object): bool => $object->type === SchemaObjectType::Table
            && ! $object->isPartition
            && ($shape->schema === null
                ? substr((string) strrchr('.'.$object->qualifiedName, '.'), 1) === $shape->table
                : $object->qualifiedName === $shape->schema.'.'.$shape->table));
    }

    /**
     * The members of a table the advice weighs: its columns, its comparable indexes, the ones that hold a key
     * or a unique constraint, and the ones the optimizer does not see.
     *
     * @return array{columns: list<string>, indexes: array<string, list<string>>, protected: list<string>, invisible: list<string>}
     */
    private function membersOf(SchemaObject $table): array
    {
        $members = static fn (string $key): array => array_map(
            static fn (array $columns): array => array_map(static fn (string $column): string => trim($column, '"`'), $columns),
            ForeignKeyIndexCoverage::parse($table->getString($key) ?? ''),
        );

        return [
            'columns' => array_values(array_filter(
                array_map(trim(...), explode(';', $table->getString('columns') ?? '')),
                static fn (string $column): bool => $column !== '',
            )),
            'indexes' => $members('comparable_indexes'),
            'protected' => array_map(strval(...), array_keys([...$members('primary_key'), ...$members('unique_indexes')])),
            'invisible' => array_map(strval(...), array_keys($members('invisible_indexes'))),
        ];
    }
}
