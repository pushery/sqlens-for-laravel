<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * Which statement a policy governs — `pg_policy.polcmd`, in words.
 *
 * The catalog stores one character, and the mapping is not guessable from it (`*` for ALL, `r` for
 * SELECT), so it is written down once here rather than repeated at every reader that touches it.
 *
 * A rule needs the distinction because the consequences differ: a permissive `SELECT` policy that
 * admits everything is a read exposure, while the same on `ALL` also lets rows be written.
 */
enum RlsCommand: string
{
    case All = 'all';
    case Select = 'select';
    case Insert = 'insert';
    case Update = 'update';
    case Delete = 'delete';

    /** The catalog's single character, mapped. Anything unknown is refused rather than guessed. */
    public static function fromCatalog(string $polcmd): ?self
    {
        return match ($polcmd) {
            '*' => self::All,
            'r' => self::Select,
            'a' => self::Insert,
            'w' => self::Update,
            'd' => self::Delete,
            default => null,
        };
    }
}
