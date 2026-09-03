<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Canonical;

/**
 * What a foreign key does to the child rows when the parent changes — in one alphabet.
 *
 * The two catalogs answer the same question in different languages, measured: PostgreSQL's
 * `pg_constraint` stores a single letter (`c`, `a`, `r`, `n`, `d`), MySQL's
 * `REFERENTIAL_CONSTRAINTS` stores the SQL words (`CASCADE`, `NO ACTION`). A rule asking "is this
 * `ON DELETE CASCADE`?" would otherwise have to know which engine it is talking to — which is the
 * coupling the whole canonicalization layer exists to remove, and it would be the kind of coupling
 * nobody notices until the rule is silently wrong on one of the two.
 *
 * The SQL words win as the canonical form: they are what a user wrote in the migration and what a
 * finding has to be able to quote back at them.
 */
enum ReferentialAction: string
{
    case NoAction = 'NO ACTION';
    case Restrict = 'RESTRICT';
    case Cascade = 'CASCADE';
    case SetNull = 'SET NULL';
    case SetDefault = 'SET DEFAULT';

    /**
     * Read either engine's spelling.
     *
     * An unrecognized value becomes {@see self::NoAction} — the SQL default, and the reading that
     * claims the least. Between two wrong answers, the one that does not invent a cascade is the
     * safer one: a rule told a key cascades will warn about data loss that cannot happen, and a
     * user who is warned about something impossible stops reading the warnings.
     */
    public static function read(string $raw): self
    {
        return match (mb_strtoupper(trim($raw))) {
            'C', 'CASCADE' => self::Cascade,
            'R', 'RESTRICT' => self::Restrict,
            'N', 'SET NULL' => self::SetNull,
            'D', 'SET DEFAULT' => self::SetDefault,
            default => self::NoAction,
        };
    }
}
