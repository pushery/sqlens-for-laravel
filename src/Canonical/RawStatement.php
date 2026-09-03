<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Subjects\MigrationSql;

/**
 * The in-flight statement a canonicalization stage receives and refines — raw or
 * partially-normalized SQL plus its provenance. Stages return a refined
 * RawStatement to keep going, or a CanonicalStatement to finalize. It is
 * immutable: a stage produces a new copy via withSql(), never mutates in place.
 */
final readonly class RawStatement
{
    public function __construct(
        public string $sql,
        public StatementOrigin $origin,
        public bool $withinTransaction,
        public ?TransactionContext $transaction = null,
    ) {}

    /** Lift the statement text and provenance off a captured migration-SQL subject. */
    public static function fromSubject(MigrationSql $subject): self
    {
        return new self(
            sql: $subject->canonicalStatement,
            origin: StatementOrigin::fromSubject($subject),
            withinTransaction: $subject->withinTransaction,
        );
    }

    /** A new instance with the normalized SQL text; the original (and the resolved context) is untouched. */
    public function withSql(string $sql): self
    {
        return new self($sql, $this->origin, $this->withinTransaction, $this->transaction);
    }

    /** A new instance carrying the resolved transaction context; the rest is untouched. */
    public function withTransactionContext(TransactionContext $transaction): self
    {
        return new self($this->sql, $this->origin, $this->withinTransaction, $transaction);
    }
}
