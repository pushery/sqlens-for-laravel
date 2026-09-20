<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * The column a not-null validation names — read once, for the rule that flags it and the sequence
 * that fixes it. PostgreSQL spells this TWO ways, and the second one arrived with 18.
 *
 * The rule already had to find the column to ask whether the migration prepares it with a CHECK.
 * The remediation needs the same name to write the sequence, and a second `preg_match` for it would
 * be the shape this package keeps removing.
 *
 * ## Why the pattern matches lowercase `set`
 *
 * In the canonical form `set` is NOT a keyword and stays lowercase, while `NOT NULL` is normalized.
 * Matching `set NOT NULL` is what distinguishes this statement from `ADD COLUMN … NOT NULL DEFAULT`,
 * which carries `NOT NULL` and no `SET` at all — and confusing the two would attach a
 * four-statement plan to a column being created.
 *
 * ## The second spelling, and why it was silent
 *
 * PostgreSQL 18 keeps not-null constraints in `pg_constraint` with `contype = 'n'` and accepts them
 * as named constraints:
 *
 * ```sql
 * ALTER TABLE orders ADD CONSTRAINT orders_email_nn NOT NULL email [NOT VALID];
 * ```
 *
 * ⚠️ **This form reached NO rule at all.** It classifies as `AddConstraint`, which this reader
 * refused, and `ConstraintShape` fell through every arm to `null` — where `null` means "nothing to
 * say" rather than "I do not know this". So the exact operation `PG.L2.SET_NOT_NULL_SCAN` exists to
 * report passed in silence, under a different spelling of itself.
 *
 * **Measured on PostgreSQL 18.0**, which is what makes this the same finding rather than a
 * lookalike: without `NOT VALID` the constraint lands `convalidated = t` — the server scanned every
 * row — and the statement holds `AccessExclusiveLock` on the table while it does.
 *
 * ⚠️ **And `NOT VALID` here is the safe form for the same reason it is elsewhere, but NOT for the
 * reason one would guess.** Measured on the same server: the `NOT VALID` variant takes
 * `AccessExclusiveLock` as well. What it removes is the SCAN, not the lock level — so the lock is
 * brief rather than absent, and a remediation promising a weaker lock would be wrong. A statement
 * already carrying it is the recommended form and draws no finding.
 */
final readonly class SetNotNullChange
{
    private function __construct(
        /** The column being made non-nullable, unquoted, as the canonical statement names it. */
        public string $column,
    ) {}

    /** The change this statement performs, or null when it performs none. */
    public static function of(MigrationStatementView $statement): ?self
    {
        // `AddConstraint` as well as `AlterTable`: the 18 spelling classifies as the former, and
        // requiring only the latter is what kept it out of every rule.
        if (! $statement->is(StatementKind::AlterTable) && ! $statement->is(StatementKind::AddConstraint)) {
            return null;
        }

        $canonical = $statement->canonical;

        if (preg_match('/\\bALTER COLUMN\\s+"?([a-z_][a-z0-9_]*)"?\\s+set\\s+NOT NULL\\b/i', $canonical, $matches) === 1) {
            return new self($matches[1]);
        }

        // The named-constraint spelling. Already `NOT VALID` is the recommended form -- it skips the
        // validating scan -- so it is not a finding, exactly as the same carve-out works for a
        // foreign key or a check.
        if (str_contains($canonical, 'NOT VALID')) {
            return null;
        }

        return preg_match('/\\bADD CONSTRAINT\\s+"?[a-z_][a-z0-9_]*"?\\s+NOT NULL\\s+"?([a-z_][a-z0-9_]*)"?/i', $canonical, $named) === 1
            ? new self($named[1])
            : null;
    }
}
