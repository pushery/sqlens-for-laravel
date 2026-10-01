<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard;

use Closure;
use Illuminate\Database\Schema\Grammars\Grammar as SchemaGrammar;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Throwable;
use WeakMap;

/**
 * Whether a statement is one Laravel's schema builder sends to ask about the schema.
 *
 * `Schema::hasTable()`, `getColumns()` and the rest write the names they ask about into the statement
 * as quoted literals. To a guard that looks for a literal where a binding belongs they look exactly
 * like concatenated input, and packages call them on every boot, so every request would log a
 * security line about the framework asking whether a table exists.
 *
 * They are recognized by SHAPE, and the shapes come from the connection's own schema grammar: every
 * introspection compiler the framework declares is compiled with stand-in names, its literals are
 * blanked in the engine's grammar, and a statement that blanks to one of those shapes is the
 * framework's. Nothing about any engine is written down here, so a framework release that changes
 * a query, or another engine's grammar, answers for itself.
 *
 * The comparison is exact apart from the literals, and a list of literals counts as one, because
 * the builder passes one schema or several. A statement that carries the framework's shape and
 * anything more is not the framework's and is reported.
 *
 * The shapes are kept per grammar OBJECT, not per class. A grammar can compile a question
 * differently for another server version of the same engine, and each connection has its own
 * grammar; a weak map lets an entry go when its connection is purged.
 */
final class SchemaIntrospection
{
    /** @var WeakMap<SchemaGrammar, array<string, true>>|null */
    private static ?WeakMap $shapes = null;

    /** Whether $sql is a statement $grammar compiles to ask about the schema. */
    public static function recognizes(string $sql, SchemaGrammar $grammar, StringLiteralMask $mask): bool
    {
        self::$shapes ??= new WeakMap;
        $shapes = self::$shapes[$grammar] ??= self::shapesOf($grammar, $mask);

        return isset($shapes[self::shape($sql, $mask)]);
    }

    /**
     * Every introspection statement the grammar compiles, as shapes.
     *
     * The compilers are the ones Laravel's base schema grammar declares, called with no schema, with
     * one and with a list, since the builder passes all three. A compiler the engine does not
     * support throws, and that only means the engine never sends such a statement.
     *
     * @return array<string, true>
     */
    private static function shapesOf(SchemaGrammar $grammar, StringLiteralMask $mask): array
    {
        $compilers = [
            $grammar->compileSchemas(...),
            static fn (): mixed => $grammar->compileTableExists(null, 'table'),
            static fn (): mixed => $grammar->compileTableExists('schema', 'table'),
            static fn (): mixed => $grammar->compileTables(null),
            static fn (): mixed => $grammar->compileTables('schema'),
            static fn (): mixed => $grammar->compileTables(['schema', 'other']),
            static fn (): mixed => $grammar->compileViews(null),
            static fn (): mixed => $grammar->compileViews('schema'),
            static fn (): mixed => $grammar->compileViews(['schema', 'other']),
            static fn (): mixed => $grammar->compileTypes(null),
            static fn (): mixed => $grammar->compileTypes('schema'),
            static fn (): mixed => $grammar->compileTypes(['schema', 'other']),
            static fn (): mixed => $grammar->compileColumns(null, 'table'),
            static fn (): mixed => $grammar->compileColumns('schema', 'table'),
            static fn (): mixed => $grammar->compileIndexes(null, 'table'),
            static fn (): mixed => $grammar->compileIndexes('schema', 'table'),
            static fn (): mixed => $grammar->compileForeignKeys(null, 'table'),
            static fn (): mixed => $grammar->compileForeignKeys('schema', 'table'),
        ];

        return array_fill_keys(array_values(array_filter(array_map(
            static fn (Closure $compile): ?string => self::compiled($compile, $mask),
            $compilers,
        ), is_string(...))), true);
    }

    /** The shape of one compiled statement, or null when the engine does not support the question. */
    private static function compiled(Closure $compile, StringLiteralMask $mask): ?string
    {
        try {
            $sql = $compile();
        } catch (Throwable) {
            return null;
        }

        return is_string($sql) && $sql !== '' ? self::shape($sql, $mask) : null;
    }

    /** The statement with its literals blanked, and a list of blanked literals read as one. */
    private static function shape(string $sql, StringLiteralMask $mask): string
    {
        $blanked = $mask->apply($sql);

        return preg_replace("/''(?:\\s*,\\s*'')+/", "''", $blanked) ?? $blanked;
    }
}
