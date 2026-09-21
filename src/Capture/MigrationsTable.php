<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

/**
 * The name of Laravel's own migrations ledger, read the way the framework reads it.
 *
 * ## Why this is a class and not a literal
 *
 * It was a literal, in two places, and both were wrong for every application that renames the
 * table. `database.migrations` has TWO shapes — the name itself (the historical form) and an array
 * carrying it under `table` (Laravel 11 and later) — and the framework narrows them in
 * `MigrationServiceProvider`. A caller that wrote `'migrations'` was not choosing a default; it
 * was overriding a decision the application had already made.
 *
 * The consequence is not a silent green, which is what makes it easy to miss: the pending resolver
 * asks `hasTable('migrations')`, gets false, and reports `NoMigrationTable`. The table exists. The
 * reader goes looking for one that is not missing, and in that application `sqlens:lint` never
 * judges a pending migration and `sqlens:drift` never resolves a pending state — permanently,
 * not as an edge case.
 *
 * ## Why the narrowing is here rather than at each reader
 *
 * Three places needed it and two had it: the driver registry narrowed it correctly for its own
 * rules, seven lines above a binding that passed the literal. One function means the third reader
 * cannot get it wrong, and a fourth inherits the answer.
 */
final readonly class MigrationsTable
{
    /** What the framework falls back to when the application says nothing. */
    public const string DEFAULT = 'migrations';

    /**
     * The configured name, or the framework's default.
     *
     * Anything that is not a non-empty string under either shape reads as "not said" — absent, a
     * number, a list. That is the honest reading: the table exists under the default name whatever
     * a malformed setting would prefer, and inventing a name from a malformed value would send
     * every reader to a table nobody has.
     */
    public static function from(mixed $configured): string
    {
        $name = is_array($configured) ? ($configured['table'] ?? null) : $configured;

        return is_string($name) && trim($name) !== '' ? trim($name) : self::DEFAULT;
    }
}
