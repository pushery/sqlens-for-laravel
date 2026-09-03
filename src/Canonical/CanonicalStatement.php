<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * The one data structure every rule works on. Immutable and versioned: from here
 * on a rule has no legitimate reason to see raw SQL — the raw text survives only
 * as provenance on the origin, never as a working surface (the grammar-drift
 * pitfall). The canonicalization is the single allowed abstraction over grammar
 * quirks.
 *
 * Statement kind and targets are typed slots the classification ticket fills.
 * They are NULLABLE on purpose: an unclassified statement reads as null (a
 * three-valued, undetermined slot) — never as an empty, harmless-looking default
 * that a rule might mistake for "nothing here". isClassified() is the guard a
 * consumer checks.
 */
final readonly class CanonicalStatement
{
    /**
     * @param  list<StatementTarget>|null  $targets  the schema objects acted on, or null while unclassified
     */
    public function __construct(
        public string $canonicalSql,
        public StatementOrigin $origin,
        public TransactionContext $transaction,
        public CanonicalFormVersion $formVersion,
        public ?StatementKind $statementKind = null,
        public ?array $targets = null,
        /**
         * The ordered column list a key-bearing statement names, or an empty list.
         *
         * ORDER is load-bearing: index coverage is a left prefix, so `(a, b)` and `(b, a)` are
         * different answers and a set would be worse than nothing here — the next reader would
         * assume the question had been considered. Produced by the classifier from the signature,
         * never by a rule re-reading the string.
         *
         * @var list<string>
         */
        public array $keyColumns = [],
    ) {}

    /** Whether the classification slots are filled — false means the kind/targets are not yet known. */
    public function isClassified(): bool
    {
        return $this->statementKind instanceof StatementKind && $this->targets !== null;
    }

    /**
     * A new instance carrying the classification; the original is untouched. Used
     * by the classification stage, not by rules.
     *
     * @param  list<StatementTarget>  $targets
     * @param  list<string>  $keyColumns
     */
    public function withClassification(StatementKind $statementKind, array $targets, array $keyColumns = []): self
    {
        return new self(
            $this->canonicalSql,
            $this->origin,
            $this->transaction,
            $this->formVersion,
            $statementKind,
            $targets,
            $keyColumns,
        );
    }
}
