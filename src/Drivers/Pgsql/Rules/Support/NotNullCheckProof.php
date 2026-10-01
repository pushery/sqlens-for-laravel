<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Canonical\CanonicalName;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\StringLiteralMask;
use Pushery\SQLens\Drivers\Pgsql\Canonical\PgsqlCanonicalization;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Whether a `CHECK (col IS NOT NULL)` stands as proof on a table by the time a statement runs.
 *
 * PostgreSQL skips the scan of `SET NOT NULL` when a VALID check constraint proves that no row of the
 * column is null. Three things make a check that proof, and each is read from the migration's
 * statements in their order rather than taken from a check somewhere in it:
 *
 * - it constrains the same table, read from the classified target of its `ADD CONSTRAINT`;
 * - it names the same column, compared the way the canonical form writes names, so `"Email"` and
 *   `email` stay two columns, as they are to PostgreSQL;
 * - it is valid before the statement runs: added without `NOT VALID`, or added `NOT VALID` and then
 *   validated by name, both earlier in the migration.
 *
 * A check on another table, one that was never validated and one added after the statement prove
 * nothing, and PostgreSQL scans the whole table in each case.
 */
final class NotNullCheckProof
{
    /** `CHECK ( <column> IS NOT NULL )`, and whether `NOT VALID` follows it. */
    private const string CHECK = '/\bCHECK\s*\(\s*('.CanonicalName::PATTERN.')\s+IS\s+NOT NULL\s*\)(\s+NOT VALID)?/i';

    /** Whether a valid not-null check on this table and column precedes the statement in its migration. */
    public static function standsBefore(MigrationStatementView $statement, StatementTarget $table, string $column): bool
    {
        $mask = StringLiteralMask::forDriver(new PgsqlCanonicalization);

        /** @var array<string, true> $awaitingValidation constraint names added NOT VALID, by qualified name */
        $awaitingValidation = [];

        foreach ($statement->migration->statements as $earlier) {
            if ($earlier->index >= $statement->statementIndex || ! self::isOn($earlier, $table)) {
                continue;
            }

            $canonical = $mask->apply($earlier->canonical);
            $constraint = $earlier->soleTarget(SchemaObjectType::Constraint)?->qualifiedName();

            if ($earlier->kind === StatementKind::AddConstraint && preg_match(self::CHECK, $canonical, $check) === 1) {
                if (CanonicalName::bare($check[1]) !== $column) {
                    continue;
                }

                if (($check[2] ?? '') === '') {
                    return true;
                }

                if ($constraint !== null) {
                    $awaitingValidation[$constraint] = true;
                }

                continue;
            }

            if ($constraint !== null && isset($awaitingValidation[$constraint]) && preg_match('/\bVALIDATE CONSTRAINT\b/i', $canonical) === 1) {
                return true;
            }
        }

        return false;
    }

    private static function isOn(MigrationStatementDigest $statement, StatementTarget $table): bool
    {
        return $statement->soleTarget(SchemaObjectType::Table)?->qualifiedName() === $table->qualifiedName();
    }
}
