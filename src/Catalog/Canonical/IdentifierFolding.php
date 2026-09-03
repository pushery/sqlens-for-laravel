<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Canonical;

/**
 * How one server treats the case of an unquoted identifier — READ from the server, never assumed.
 *
 * The assumption is where this goes wrong. PostgreSQL is simple: unquoted folds to lower. MySQL
 * depends on `lower_case_table_names`, which is a SERVER setting with three values and a platform
 * default that differs — measured on the Herd MySQL 8.4 used to build this, it is **2**, not the 0
 * a Linux-shaped assumption would predict. A canonicalization that guessed would report every table
 * as renamed the first time it ran somewhere else.
 */
enum IdentifierFolding: string
{
    /** Fold to lower case. PostgreSQL's unquoted rule, and MySQL's `lower_case_table_names = 1`. */
    case Lower = 'lower';

    /**
     * Keep the name as stored, and compare case-insensitively.
     *
     * MySQL's `lower_case_table_names = 2` — the macOS default. Names are preserved on disk but two
     * spellings are the same object, so the comparison key is folded while the displayed name is not.
     */
    case PreserveCompareInsensitive = 'preserve_compare_insensitive';

    /** Keep the name, and treat two spellings as two objects. MySQL's `0`, the Linux default. */
    case Preserve = 'preserve';

    /**
     * What MySQL's `lower_case_table_names` means, by value.
     *
     * An unknown value is {@see self::Preserve} — the reading that treats two spellings as two
     * objects, which produces a visible extra object rather than a silently merged pair. Between two
     * wrong answers, the one that shows up is the better one.
     */
    public static function forLowerCaseTableNames(int $setting): self
    {
        return match ($setting) {
            1 => self::Lower,
            2 => self::PreserveCompareInsensitive,
            default => self::Preserve,
        };
    }

    /** The key two names are compared under — what decides whether they are the same object. */
    public function comparisonKey(string $identifier): string
    {
        return $this === self::Preserve ? $identifier : mb_strtolower($identifier);
    }

    /** The name a user is shown. Only a folding server rewrites it. */
    public function displayName(string $identifier): string
    {
        return $this === self::Lower ? mb_strtolower($identifier) : $identifier;
    }
}
