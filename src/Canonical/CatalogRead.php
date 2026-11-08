<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Generator;
use Pushery\SQLens\Canonical\Classification\StatementClassificationProfile;
use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * The relation of the engine's system catalog that a `SELECT` reads, found in its canonical SQL.
 *
 * `Schema::hasTable()`, `hasColumn()`, `getColumns()` and their siblings ask the catalog, and a migration
 * asks it to decide what to do next. Pretend mode answers every query with nothing, so a pretend capture
 * that holds such a read cannot know what the migration runs against a real schema. A read of data is
 * another matter: a migration often counts rows only to log the number, and that read decides nothing.
 *
 * What the catalog is belongs to the driver ({@see StatementClassificationProfile}): a relation qualified
 * by one of its catalog schemas, or an unqualified name it lists. A name followed by `(` is a function,
 * so `pg_catalog.set_config(…)` and `pg_advisory_xact_lock(…)` read no relation. Literals, comments and
 * dollar-quoted bodies are skipped the way the classifier skips them, so a catalog name inside a string
 * decides nothing.
 */
final readonly class CatalogRead
{
    /**
     * The catalog relation the statement reads, lower case and qualified as written, or null when the
     * statement is no `SELECT` or reads no relation of the catalog.
     */
    public static function in(string $sql, DriverCanonicalization $driver): ?string
    {
        $schemas = null;
        $relations = [];

        foreach (self::namesIn($sql, $driver) as [$chain, $called]) {
            // Only a SELECT reads, and its lead word is the statement's first name. A `CREATE TABLE` that
            // names its table after a relation of the catalog creates a table of its own. The profile is
            // read once the lead has said it is needed.
            if ($schemas === null) {
                if (strcasecmp($chain, 'SELECT') !== 0) {
                    return null;
                }

                $profile = $driver->statementClassification();
                $schemas = array_fill_keys(array_map(strtolower(...), $profile->catalogSchemas), true);
                $relations = array_fill_keys(array_map(strtolower(...), $profile->catalogRelations), true);

                continue;
            }

            if ($called) {
                continue;
            }

            $identifier = Identifier::parse($chain, $driver);

            if ($identifier instanceof CanonicalizationFailure) {
                continue;
            }

            $name = strtolower($identifier->catalogName($driver));
            $read = $identifier->schema instanceof IdentifierComponent
                ? isset($schemas[strtolower(new Identifier(null, $identifier->schema)->catalogName($driver))])
                : isset($relations[$name]);

            if ($read) {
                return $name;
            }
        }

        return null;
    }

    /**
     * Each name of the statement, a keyword or an identifier chain, beside whether a `(` follows it.
     *
     * @return Generator<int, array{string, bool}>
     */
    private static function namesIn(string $sql, DriverCanonicalization $driver): Generator
    {
        $quote = $driver->quotingCharacter();
        $literals = $driver->stringLiteralDelimiters();
        $markers = $driver->commentSyntaxes();
        $lineComments = array_values(array_filter($markers, static fn (string $marker): bool => $marker !== '/*'));
        $blockComments = in_array('/*', $markers, true);
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            if (ScanAt::firstOf($sql, $i, $lineComments) !== null) {
                $newline = strpos($sql, "\n", $i);
                $i = $newline === false ? $length : $newline;

                continue;
            }

            if ($blockComments && ScanAt::startsWith($sql, $i, '/*')) {
                $i = QuotedSpan::endOfBlockComment($sql, $i, $driver->nestsBlockComments()) ?? $length;

                continue;
            }

            if ($driver->supportsDollarQuotedStrings() && $sql[$i] === '$' && preg_match('/\G\$\w*\$/', $sql, $tag, 0, $i) === 1) {
                $close = strpos($sql, $tag[0], $i + strlen($tag[0]));
                $i = $close === false ? $length : $close + strlen($tag[0]);

                continue;
            }

            $literal = ScanAt::firstOf($sql, $i, $literals);

            if ($literal !== null) {
                $i = QuotedSpan::endOfLiteral($sql, $i, $literal, $driver->usesBackslashStringEscapes()) ?? $length;

                continue;
            }

            if (self::startsAPart($sql[$i], $quote)) {
                $end = self::endOfChain($sql, $i, $quote);
                $next = $end + strspn($sql, " \t\r\n", $end);

                yield [substr($sql, $i, $end - $i), ($sql[$next] ?? '') === '('];

                $i = $end;

                continue;
            }

            $i++;
        }
    }

    /** The index just past the `part('.'part)*` identifier chain that starts at `$start`. */
    private static function endOfChain(string $sql, int $start, string $quote): int
    {
        $length = strlen($sql);
        $j = $start;

        while (true) {
            if ($sql[$j] === $quote) {
                $close = QuotedSpan::endOfQuotedIdentifier($sql, $j, $quote);

                if ($close === null) {
                    return $length;
                }

                $j = $close;
            } else {
                while ($j < $length && preg_match('/[A-Za-z0-9_$\x80-\xff]/', $sql[$j]) === 1) {
                    $j++;
                }
            }

            if ($j + 1 < $length && $sql[$j] === '.' && self::startsAPart($sql[$j + 1], $quote)) {
                $j++;

                continue;
            }

            return $j;
        }
    }

    private static function startsAPart(string $char, string $quote): bool
    {
        return ($quote !== '' && $char === $quote) || preg_match('/[A-Za-z_\x80-\xff]/', $char) === 1;
    }
}
