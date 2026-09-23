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
 * `null` covers everything the rule has nothing to say about, including the two safe forms — a
 * foreign key or check already marked `NOT VALID`, and a primary key or unique promoted from an
 * index with `USING INDEX`. Those are the exact sequences the templates recommend, so firing on
 * them would cry wolf on our own advice; keeping that exit beside the classification is what stops
 * a later reader from re-deciding it one way in the rule and another in the template.
 *
 * **And `null` means only that.** A form the arms do not recognize is {@see self::Unrecognized},
 * never `null`, so an unconsidered constraint kind cannot look like a considered-and-cleared one,
 * and a rule turns it into an `undetermined` rather than a silent pass. The deliberate exits are
 * `null`, each one written down where it is taken.
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
     * EXCLUDE: blocking, and the only shape here with no safe sequence to offer.
     *
     * The server builds the backing index under `AccessExclusiveLock` — measured on 18.0, together
     * with a `ShareLock` on the same table — and `NOT VALID` is not accepted: `ALTER TABLE … EXCLUDE
     * USING gist (…) NOT VALID` answers *"EXCLUDE constraints cannot be marked NOT VALID"*. There is
     * no `USING INDEX` promotion either, the way there is for a primary key or a unique.
     *
     * So the honest finding names a maintenance window rather than a sequence. Saying nothing was the
     * old behavior and the worse one: this blocks writes for the whole build, on a live table.
     */
    case Exclude;

    /**
     * An `ADD CONSTRAINT` form this classifier does not know.
     *
     * **This case keeps `null` to one meaning.** `null` is the deliberate exit — a safe form, or a
     * table born in this migration. Handing back the same `null` for anything the arms do not
     * recognize would make a constraint kind nobody has thought about look exactly like one that has
     * been considered and cleared.
     *
     * The case is concrete: PostgreSQL 18's named not-null constraint is such a kind, and that
     * statement performs the very scan `PG.L2.SET_NOT_NULL_SCAN` exists to report.
     *
     * A rule seeing this answers `undetermined` with a reason, never silence. "I do not recognize this
     * statement" and "this statement is fine" are different sentences, and only one of them is honest
     * about a form the classifier has never seen.
     */
    case Unrecognized;

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

        // Two carve-outs, and they answer two different questions.
        //
        // The first: nothing live is locked at all, because every table this constraint names was
        // born in this migration. True whatever rows the migration put into them — nobody is
        // waiting on a table that did not exist a moment ago.
        //
        // The second: the altered table is born EMPTY here, so the validating scan that separates
        // this form from `NOT VALID` has nothing to scan. The referenced table may well be live,
        // and its lock is real — but it is the same lock the recommended form takes, held for the
        // same instant, so the advice would split one migration into two and shorten nothing. That
        // case is the ordinary `Schema::create()` with `foreignId()->constrained()`, which used to
        // make every new related table red from level 2 up; a consumer read it back to us after
        // seeing the index rule stay silent on the very same migration.
        if (TouchedTables::allCreatedHere($statement) || TouchedTables::subjectBornEmptyHere($statement)) {
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

        if (preg_match('/\bUNIQUE\b/', $canonical) === 1) {
            return self::Unique;
        }

        if (preg_match('/\bEXCLUDE\b/', $canonical) === 1) {
            return self::Exclude;
        }

        // The named not-null spelling belongs to `PG.L2.SET_NOT_NULL_SCAN`, which reads it through
        // {@see SetNotNullChange} and reports the identical operation. Returning a shape here would
        // report one statement twice, under two rule ids, with two different remediations -- and the
        // scan rule's is the right one, because this IS a not-null validation and not a constraint
        // whose index has to be built. A deliberate `null`, with the owner named.
        if (preg_match('/\bADD CONSTRAINT\s+"?[a-z_][a-z0-9_]*"?\s+NOT NULL\b/i', $canonical) === 1) {
            return null;
        }

        // Everything else. NOT silence -- see the case's own docblock.
        return self::Unrecognized;
    }

    /** The keyword `ADD CONSTRAINT … USING INDEX` needs, for the two shapes that use it. */
    public function promotionKeyword(): string
    {
        return $this === self::PrimaryKey ? 'PRIMARY KEY' : 'UNIQUE';
    }
}
