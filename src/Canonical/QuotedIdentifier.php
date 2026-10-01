<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * An object name written the way SQL reads it back as that name and nothing else: every part
 * quoted, the quote character doubled inside it.
 *
 * A name out of the catalog is chosen by whoever may create objects in the schema, and on most
 * Laravel setups that is the application's own role. Put into a statement as it is, a table named
 * `y; DROP TABLE users; --_old` turns the advice `DROP TABLE public.y; DROP TABLE users; --_old;`
 * into two statements for whoever pastes it, and psql runs the second after the first one fails.
 * Even a harmless `MixedCase` name reaches another object unquoted, because PostgreSQL folds it to
 * lower case. Quoted, the name can only be the one it is.
 *
 * The quote character is the caller's, because it is the engine's: a double quote in PostgreSQL, a
 * backtick in MySQL. An empty part is left out, so a name the catalog gave without a schema stays
 * unqualified rather than gaining an empty one.
 */
final readonly class QuotedIdentifier
{
    public static function of(string $quote, string ...$parts): string
    {
        return implode('.', array_map(
            static fn (string $part): string => $quote.str_replace($quote, $quote.$quote, $part).$quote,
            array_values(array_filter($parts, static fn (string $part): bool => $part !== '')),
        ));
    }
}
