<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * One classified InnoDB DDL operation: how it runs on the reference server, under which
 * conditions, and with which provenance. The typed form of a single entry in the online-DDL
 * matrix data file, produced by {@see OnlineDdlMatrix}. The downtime mapper reads
 * `algorithm`, `rebuildsTable`, `permitsConcurrentDml` and `lock`; the rest is metadata a
 * later version-aware resolver and the maintenance process rely on.
 */
final readonly class MatrixEntry
{
    /**
     * @param  list<MatrixCondition>  $conditions
     * @param  list<MatrixSource>  $sources  never empty — the schema requires at least one
     */
    public function __construct(
        public string $id,
        public string $operation,
        public OnlineDdlAlgorithm $algorithm,
        public bool $rebuildsTable,
        public bool $permitsConcurrentDml,
        public LockImplication $lock,
        public string $minVersion,
        public ?string $maxVersion,
        public array $conditions,
        public array $sources,
        public string $notes,
        public string $stability,
    ) {}

    /**
     * Whether an `ALGORITHM=` / `LOCK=` clause on this operation means anything at all.
     *
     * False for the operations where the clause either does not parse or parses and is IGNORED —
     * `EXCHANGE PARTITION` accepts even `ALGORITHM=COPY, LOCK=NONE`, a self-contradictory pair every
     * other statement rejects. A remediation that suggested the clause there would hand somebody a
     * guarantee the server never makes, which is the silent green this package exists to catch.
     *
     * It lives here rather than in the template that asks, because the axes belong to this
     * namespace: a file outside it evaluating {@see $algorithm} would be a second decision table,
     * and the guard beside the classifier says so.
     */
    public function clauseIsMeaningful(): bool
    {
        return $this->algorithm !== OnlineDdlAlgorithm::NotApplicable;
    }

    /** The `ALGORITHM=` value for this entry, spelled the way the server expects it. */
    public function algorithmClause(): string
    {
        return strtoupper($this->algorithm->value);
    }

    /** The `LOCK=` value for this entry, spelled the way the server expects it. */
    public function lockClause(): string
    {
        return strtoupper($this->lock->value);
    }

    /**
     * Whether running this operation means rewriting the whole table.
     *
     * A FACT about the operation, named so a reader outside this namespace can act on it without
     * evaluating an axis: what to DO about a rewrite — plan a window, stage the change — is a
     * decision that belongs to whoever is advising, and what a rewrite IS belongs here.
     */
    public function rewritesTheTable(): bool
    {
        return $this->rebuildsTable;
    }
}
