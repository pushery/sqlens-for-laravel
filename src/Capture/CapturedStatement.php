<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\TransactionContext;
use Pushery\SQLens\Canonical\TransactionMode;
use Pushery\SQLens\Subjects\MigrationDirection;

/**
 * One statement a capture produced, in every form it passes through.
 *
 * A statement is captured raw (grammar output plus bindings), then substituted
 * (bindings inlined, so a rule reads one complete string), then canonicalized.
 * The later two forms are filled by their own stages, so they are nullable HERE
 * and only here — an accessor that silently returned the raw text when the
 * canonical form is missing would hand a rule exactly the grammar quirks the
 * canonicalization layer exists to remove.
 *
 * The canonicalization stage also CLASSIFIES the statement — what it does and what
 * it acts on — and that classification rides along here too. It is routing metadata,
 * not report content: it is how a migration-level rule learns that an index targets
 * a table the same migration created, and it is deliberately kept off {@see toArray()}
 * (the wire form) because a report consumer reads the canonical SQL, not the parse.
 *
 * `direction` is required and has no default on purpose. The pretend run only
 * ever produces `up`, so a default would be free and correct today — and would
 * silently mislabel every `down` statement the moment the shadow roundtrip
 * starts filling them. The field exists now so the roundtrip fills it rather
 * than reopening a value object the whole capture layer already depends on.
 */
final readonly class CapturedStatement
{
    /**
     * @param  list<mixed>  $bindings
     * @param  list<StatementTarget>|null  $targets  the classified targets, or null while unclassified
     */
    public function __construct(
        public string $rawSql,
        public array $bindings,
        public int $sequence,
        public MigrationDirection $direction,
        public bool $withinTransaction,
        public string $connectionName,
        public string $driver,
        public ?string $substitutedSql = null,
        public ?string $canonicalSql = null,
        public ?StatementKind $statementKind = null,
        public ?array $targets = null,
        /**
         * The RESOLVED transaction mode, once the canonicalization has decided it.
         *
         * Distinct from `$withinTransaction`, which is the migrator's own flag and only
         * ever yes/no. The resolver can reach a third answer — an explicit transaction
         * opening inside the migrator's, an unbalanced marker, a driver that declares no
         * transaction control — and flattening that to "no" is how a lock-hygiene rule
         * ends up silent on a statement it could not reason about. Null while the
         * statement has not been through canonicalization.
         */
        public ?TransactionMode $transactionMode = null,
        /**
         * The ordered column list this statement names, or an empty list.
         *
         * @var list<string>
         */
        public array $keyColumns = [],
    ) {}

    /**
     * The same statement with its bindings inlined. Returns a new instance —
     * every stage hands the next one a fresh value object rather than mutating
     * a shared one, so a later stage can never change what an earlier one saw.
     */
    public function withSubstitutedSql(string $substitutedSql): self
    {
        return new self(
            rawSql: $this->rawSql,
            bindings: $this->bindings,
            sequence: $this->sequence,
            direction: $this->direction,
            withinTransaction: $this->withinTransaction,
            connectionName: $this->connectionName,
            driver: $this->driver,
            substitutedSql: $substitutedSql,
            canonicalSql: $this->canonicalSql,
            statementKind: $this->statementKind,
            targets: $this->targets,
            transactionMode: $this->transactionMode,
        );
    }

    /** The same statement with its canonical form attached. */
    public function withCanonicalSql(string $canonicalSql): self
    {
        return new self(
            rawSql: $this->rawSql,
            bindings: $this->bindings,
            sequence: $this->sequence,
            direction: $this->direction,
            withinTransaction: $this->withinTransaction,
            connectionName: $this->connectionName,
            driver: $this->driver,
            substitutedSql: $this->substitutedSql,
            canonicalSql: $canonicalSql,
            statementKind: $this->statementKind,
            targets: $this->targets,
            transactionMode: $this->transactionMode,
        );
    }

    /**
     * The same statement carrying the transaction mode the resolver decided on.
     *
     * Set by the canonicalizing decorator, which is the only place that has the resolved
     * {@see TransactionContext} in hand. A statement that never
     * reached canonicalization keeps null, and a rule reading null knows it was never told
     * rather than being told "not in a transaction".
     */
    public function withTransactionMode(TransactionMode $transactionMode): self
    {
        return new self(
            rawSql: $this->rawSql,
            bindings: $this->bindings,
            sequence: $this->sequence,
            direction: $this->direction,
            withinTransaction: $this->withinTransaction,
            connectionName: $this->connectionName,
            driver: $this->driver,
            substitutedSql: $this->substitutedSql,
            canonicalSql: $this->canonicalSql,
            statementKind: $this->statementKind,
            targets: $this->targets,
            transactionMode: $transactionMode,
        );
    }

    /**
     * The same statement carrying its canonical classification — what it does and
     * what it acts on. Set by the canonicalizing decorator when the driver classified
     * the statement; a statement the driver could not classify keeps null here and
     * reaches a rule unclassified rather than mislabeled.
     *
     * @param  list<StatementTarget>  $targets
     * @param  list<string>  $keyColumns
     */
    public function withClassification(StatementKind $statementKind, array $targets, array $keyColumns = []): self
    {
        return new self(
            rawSql: $this->rawSql,
            bindings: $this->bindings,
            sequence: $this->sequence,
            direction: $this->direction,
            withinTransaction: $this->withinTransaction,
            connectionName: $this->connectionName,
            driver: $this->driver,
            substitutedSql: $this->substitutedSql,
            canonicalSql: $this->canonicalSql,
            statementKind: $statementKind,
            targets: $targets,
            transactionMode: $this->transactionMode,
            keyColumns: $keyColumns,
        );
    }

    /**
     * Whether this statement has reached the form a rule is allowed to read.
     * Callers ask this instead of null-checking, so "not canonicalized yet" can
     * never be confused with "canonicalized to an empty string".
     */
    public function isCanonicalized(): bool
    {
        return $this->canonicalSql !== null;
    }

    /** Whether the bindings have been inlined into a single complete statement. */
    public function isSubstituted(): bool
    {
        return $this->substitutedSql !== null;
    }

    /**
     * A deterministic array projection with a fixed key order — the wire form.
     * Absent later-stage forms are emitted as null rather than omitted: which
     * stages a statement has passed is information a report must not lose.
     *
     * @return array{raw_sql: string, bindings: list<mixed>, sequence: int, direction: string, within_transaction: bool, connection: string, driver: string, substituted_sql: string|null, canonical_sql: string|null}
     */
    public function toArray(): array
    {
        return [
            'raw_sql' => $this->rawSql,
            'bindings' => $this->bindings,
            'sequence' => $this->sequence,
            'direction' => $this->direction->value,
            'within_transaction' => $this->withinTransaction,
            'connection' => $this->connectionName,
            'driver' => $this->driver,
            'substituted_sql' => $this->substitutedSql,
            'canonical_sql' => $this->canonicalSql,
        ];
    }
}
