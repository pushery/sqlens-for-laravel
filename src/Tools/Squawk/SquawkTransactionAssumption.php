<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

use Pushery\SQLens\Canonical\CanonicalStatement;
use Pushery\SQLens\Canonical\TransactionMode;

/**
 * Whether the tool should assume the statements run inside a transaction.
 *
 * Read off the canonical transaction context, never regexed out of the SQL. The canonicalization
 * already resolved this from the migrator's flag, the driver's capabilities and the statement
 * stream's own markers; a second reading here would be a second answer, and the two would part
 * ways the first time one of those inputs changed.
 *
 * Derived per MIGRATION, because one invocation carries one assumption. Laravel wraps a migration
 * in a transaction unless it says otherwise, so a run with a `$withinTransaction = false`
 * migration among ordinary ones has two answers — and a single global assumption would apply the
 * majority's to the exception.
 */
final readonly class SquawkTransactionAssumption
{
    /**
     * The assumption for one migration's statements, or the named reason there is none.
     *
     * Three ways to have no answer, all ending in the same named reason and none of them ending
     * in a guess: nothing to derive from, a context the canonicalization itself could not
     * establish, and statements that DISAGREE. The last is the interesting one — an explicit
     * transaction opened partway through a migration is a real shape, and choosing either
     * assumption would be choosing one for the statements it does not fit.
     *
     * @param  list<CanonicalStatement>  $statements  the statements of ONE migration
     */
    public static function forMigration(array $statements): bool|SquawkFailureReason
    {
        if ($statements === []) {
            return SquawkFailureReason::TransactionContextUnknown;
        }

        $answers = [];

        foreach ($statements as $statement) {
            if ($statement->transaction->mode === TransactionMode::Undetermined) {
                return SquawkFailureReason::TransactionContextUnknown;
            }

            $answers[$statement->transaction->withinTransaction() ? 'inside' : 'outside'] = true;
        }

        return count($answers) === 1
            ? array_key_exists('inside', $answers)
            : SquawkFailureReason::TransactionContextUnknown;
    }
}
