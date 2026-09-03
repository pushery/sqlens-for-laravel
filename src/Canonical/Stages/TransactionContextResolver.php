<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Canonical\TransactionContext;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Resolves the transaction context ONCE, centrally, and hangs it on the statement
 * so no rule and no adapter ever reaches for Laravel's migrator internals again.
 * It reads three sources — the migration's `$withinTransaction` flag (already
 * lifted onto the RawStatement), the driver's DDL-transaction capability, and the
 * transaction markers the driver declares — and never opens a connection or starts
 * a transaction: the determination is purely static.
 *
 * The resolution is deliberately per-statement and three-valued. A normal
 * statement runs in the migrator's implicit transaction only when the migration
 * asks for it AND the engine actually wraps DDL — so the same migration under an
 * engine that commits DDL implicitly (MySQL) gets a different, reasoned `None`. An
 * explicit opener starts an explicit transaction; a lone closer, a conditional
 * opener inside the migrator transaction, an unresolvable migration class, or a
 * driver that declares no markers each yield an `Undetermined` context with its
 * own reason — never a guess.
 *
 * A stage: it stores the resolved context on the RawStatement (it does not
 * finalize), so the classifier that finalizes the pipeline reads it straight off
 * the statement.
 */
final readonly class TransactionContextResolver implements CanonicalizationStage
{
    public function __construct(private DriverCanonicalization $driver) {}

    public function __invoke(RawStatement $statement, SubjectContext $context): mixed
    {
        return $statement->withTransactionContext($this->resolve($statement));
    }

    private function resolve(RawStatement $statement): TransactionContext
    {
        $markers = $this->driver->transactionMarkers();
        if ($markers->openers === [] && $markers->closers === []) {
            // (d) the driver declares no transaction vocabulary — we cannot reason
            // about markers, so the context is undetermined, not assumed.
            return TransactionContext::undetermined('the driver declares no transaction-control markers');
        }

        if (trim($statement->origin->migrationClass) === '') {
            // (c) the migration class is unresolvable, so $withinTransaction is not determinable.
            return TransactionContext::undetermined('the migration class is unresolvable; withinTransaction is not determinable');
        }

        $lead = $this->leadingKeyword($statement->sql);

        if ($lead !== null && in_array($lead, $this->upper($markers->closers), true)) {
            // (b) a closing marker on its own has no visible opening transaction.
            return TransactionContext::undetermined(sprintf('a %s marker with no visible opening transaction — unbalanced', $lead));
        }

        if ($lead !== null && in_array($lead, $this->upper($markers->openers), true)) {
            // (a) an explicit opener inside the migrator transaction is conditional or nested.
            return $statement->withinTransaction
                ? TransactionContext::undetermined('an explicit transaction opens inside the migrator transaction — conditional or nested transaction logic')
                : TransactionContext::explicitTransaction();
        }

        if ($statement->withinTransaction) {
            return $this->driver->supportsDdlTransactions()
                ? TransactionContext::implicitMigratorTransaction()
                : TransactionContext::none('the engine commits DDL implicitly; the migrator transaction does not wrap it');
        }

        return TransactionContext::none();
    }

    private function leadingKeyword(string $sql): ?string
    {
        return preg_match('/^\s*([A-Za-z_]\w*)/', $sql, $matches) === 1
            ? mb_strtoupper($matches[1])
            : null;
    }

    /**
     * @param  list<string>  $words
     * @return list<string>
     */
    private function upper(array $words): array
    {
        return array_map(mb_strtoupper(...), $words);
    }
}
