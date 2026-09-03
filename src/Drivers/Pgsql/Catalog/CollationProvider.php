<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

/**
 * PostgreSQL's single-character provider code, given a name.
 *
 * Its own class because the mapping is engine VOCABULARY, and the core is kept free of that: a rule
 * reading `'c'` would be carrying a catalog detail it has no business knowing, and a reader inlining
 * the match would leave the mapping untestable except through whatever providers the developer's
 * machine happens to have. Measured on one such machine: `libc` only, and zero user-created
 * collations — so three of the five arms were unreachable from any live test.
 *
 * An unknown code maps to `unknown` rather than throwing. A provider PostgreSQL adds in a later
 * major is not a reason to fail an audit of everything else, and a rule that receives `unknown`
 * reports what it can measure and names the provider it could not identify.
 */
final readonly class CollationProvider
{
    /** The provider name for a `pg_database.datlocprovider` / `pg_collation.collprovider` code. */
    public static function forCode(string $code): string
    {
        return match ($code) {
            'c' => 'libc',
            'i' => 'icu',
            'b' => 'builtin',
            'd' => 'default',
            default => 'unknown',
        };
    }
}
