<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Rules\TouchedTables;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * Which KIND of constraint an `ADD CONSTRAINT` installs — the one reading, shared by the rule that
 * flags it and the template that fixes it.
 *
 * ## Why this is a type and not a private method
 *
 * The two are genuinely different sequences, and picking the wrong one is worse than saying
 * nothing. `NOT VALID` is not accepted on a PRIMARY KEY or a UNIQUE constraint at all, so material
 * that recommended it there would be advice PostgreSQL refuses — a fix that fails at the moment
 * somebody trusts it. The rule already has to make this distinction to word its finding; the
 * template has to make it to build the sequence. Two readings of one fact is two chances to
 * disagree, and the disagreement would be invisible: each half looks correct on its own.
 *
 * ## Why the exits live here too
 *
 * `null` covers everything the rule has nothing to say about, INCLUDING the two safe forms — a
 * foreign key or check already marked `NOT VALID`, and a primary key or unique promoted from an
 * index with `USING INDEX`. Those are the exact sequences the templates recommend, so firing on
 * them would cry wolf on our own advice; keeping that exit beside the classification is what stops
 * a later reader from re-deciding it one way in the rule and another in the template.
 */
enum ConstraintShape
{
    /**
     * FOREIGN KEY or CHECK: the two PostgreSQL accepts `NOT VALID` on.
     *
     * Held as one case rather than split, because the safe sequence is byte-identical for both —
     * add unvalidated, validate in a later migration — and a distinction that changes nothing
     * downstream is a distinction somebody will eventually branch on for no reason.
     */
    case NotValidCapable;

    /** PRIMARY KEY: promoted from a concurrently-built unique index, never added `NOT VALID`. */
    case PrimaryKey;

    /** UNIQUE: the same promotion, under its own keyword. */
    case Unique;

    /**
     * What this statement adds, or null when this rule has nothing to say about it.
     *
     * Reads the canonical form for the constraint keywords — which are normalized there — and the
     * classification for the tables. Never Laravel's raw grammar.
     */
    public static function of(MigrationStatementView $statement): ?self
    {
        // A constraint add on an existing table. A CREATE TABLE with inline constraints is a
        // different kind and excluded: its constraints land on a table being born, which the
        // same-migration exception below would clear anyway.
        if (! $statement->is(StatementKind::AddConstraint) && ! $statement->is(StatementKind::AlterTable)) {
            return null;
        }

        $canonical = $statement->canonical;

        if (preg_match('/\bADD (CONSTRAINT|PRIMARY KEY|UNIQUE)\b/', $canonical) !== 1) {
            return null;
        }

        // Locks nothing live only when every table this constraint touches is born in this
        // migration — for a foreign key that means the referenced table too.
        if (TouchedTables::allCreatedHere($statement)) {
            return null;
        }

        if (str_contains($canonical, 'FOREIGN KEY') || preg_match('/\bCHECK\b/', $canonical) === 1) {
            // Already NOT VALID is the safe form, and it is what the template recommends.
            return str_contains($canonical, 'NOT VALID') ? null : self::NotValidCapable;
        }

        // `ADD CONSTRAINT … USING INDEX` promotes an already-built index WITHOUT the validating
        // scan — the exact safe form recommended below, so it draws no finding either.
        if (str_contains($canonical, 'USING INDEX')) {
            return null;
        }

        if (str_contains($canonical, 'PRIMARY KEY')) {
            return self::PrimaryKey;
        }

        return preg_match('/\bUNIQUE\b/', $canonical) === 1 ? self::Unique : null;
    }

    /** The keyword `ADD CONSTRAINT … USING INDEX` needs, for the two shapes that use it. */
    public function promotionKeyword(): string
    {
        return $this === self::PrimaryKey ? 'PRIMARY KEY' : 'UNIQUE';
    }
}
