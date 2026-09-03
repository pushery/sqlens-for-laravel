<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Lifecycle;

use Pushery\SQLens\Rules\AbstractSafetyRule;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * The base of the driver-neutral migration-lifecycle rule family.
 *
 * These rules judge what a migration DOES rather than what a specific engine makes of a
 * statement — a missing down(), a WHERE-less bulk write, DML mixed into a schema change.
 * The behavior is the same on PostgreSQL and MySQL, so the family is Core, not under a
 * driver: it extends the same driver-neutral {@see AbstractSafetyRule} the PostgreSQL
 * family does, and adds nothing but a name, so a lifecycle rule reads as one of a family
 * and a future lifecycle-only convention has one obvious home. Their ids live in the
 * `GEN.*` (driver-neutral) namespace.
 */
abstract class AbstractLifecycleRule extends AbstractSafetyRule
{
    /**
     * Whether this statement is the migration's FIRST — the one a per-migration fact is
     * reported on.
     *
     * Several rules in this family judge the migration rather than the statement (is there a
     * `down()`? does it destroy more than `up()` built?). Repeating such a verdict on every
     * statement would bury the per-statement findings under it, so each is reported once, and
     * "once" means on the first statement.
     *
     * The index is read from the migration's own ordered stream rather than assumed to be
     * zero: the capture sequence is what the digests carry, and a rule that hard-coded 0 would
     * report on nothing at all if a run ever started numbering elsewhere.
     */
    final protected function isFirstStatement(MigrationStatementView $statement): bool
    {
        $first = $statement->migration->statements[0] ?? null;

        return $first instanceof MigrationStatementDigest && $first->index === $statement->statementIndex;
    }
}
