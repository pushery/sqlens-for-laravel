<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * The column an `ALTER COLUMN … SET NOT NULL` names — read once, for the rule that flags it and the
 * sequence that fixes it.
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
        if (! $statement->is(StatementKind::AlterTable)) {
            return null;
        }

        if (preg_match('/\\bALTER COLUMN\\s+"?([a-z_][a-z0-9_]*)"?\\s+set\\s+NOT NULL\\b/i', $statement->canonical, $matches) !== 1) {
            return null;
        }

        return new self($matches[1]);
    }
}
