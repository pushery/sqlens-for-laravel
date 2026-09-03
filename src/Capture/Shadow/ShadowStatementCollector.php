<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Capture\CaptureSection;

/**
 * Gathers the statements a single migration emitted during a real shadow run, in
 * execution order, dropping noise as it goes.
 *
 * It is deliberately MUTABLE: a query listener on the shadow connection feeds it one
 * statement at a time as the migration runs, so it accumulates across a scope rather
 * than being built once. The runner resets it before each migration and takes its
 * contents after — the boundary between migrations is the reset, not a count or a
 * heuristic, so attribution is exact.
 *
 * The raw SQL and the bindings are kept SEPARATE, exactly as `DB::listen` reports
 * them and exactly as the pretend log's are carried, because turning them into one
 * canonical string is the shared substitution and canonicalization layer's job —
 * the shadow path grows no second inliner.
 */
final class ShadowStatementCollector
{
    /** @var list<array{sql: string, bindings: list<mixed>}> */
    private array $bucket = [];

    public function __construct(
        private readonly ShadowNoiseFilter $filter,
        private readonly string $migrationsTable,
        private readonly string $connectionName,
        private readonly string $driver,
    ) {}

    /**
     * Record one statement the listener reported. Noise — repository bookkeeping,
     * session setup, transaction brackets — is dropped here, so it never reaches a
     * subject.
     *
     * @param  array<array-key, mixed>  $bindings
     */
    public function record(string $sql, array $bindings): void
    {
        if ($this->filter->isRuleInput($sql, $this->migrationsTable)) {
            $this->bucket[] = ['sql' => $sql, 'bindings' => array_values($bindings)];
        }
    }

    /** Clear the bucket at the start of a migration. */
    public function reset(): void
    {
        $this->bucket = [];
    }

    /**
     * Take the collected statements as ordered captured statements and clear the
     * bucket. The sequence is a fresh zero-based ordinal — the statement's order in
     * the migration, not whatever the listener's timing produced.
     *
     * @return list<CapturedStatement>
     */
    public function take(CaptureSection $section, bool $withinTransaction): array
    {
        $statements = [];
        $sequence = 0;

        foreach ($this->bucket as $entry) {
            $statements[] = new CapturedStatement(
                rawSql: $entry['sql'],
                bindings: $entry['bindings'],
                sequence: $sequence,
                direction: $section->direction(),
                withinTransaction: $withinTransaction,
                connectionName: $this->connectionName,
                driver: $this->driver,
            );
            $sequence++;
        }

        $this->reset();

        return $statements;
    }
}
