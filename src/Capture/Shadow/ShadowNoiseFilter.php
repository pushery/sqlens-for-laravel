<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * Decides which statements captured during a real shadow `migrate` are rule input
 * and which are noise — the deterministic, documented filter the truth-mode capture
 * needs so a rule never judges the plumbing.
 *
 * Three kinds of statement are captured but are NOT the migration's schema change:
 *
 *   - The migration repository's own bookkeeping — every write and read of the
 *     `migrations` table. It records which migrations ran; it is never something a
 *     migration author wrote, so it must never reach a rule.
 *   - Connection setup — `SET …` session statements (the session guard's timeouts,
 *     the character-set handshake). They configure the session, not the schema.
 *   - Transaction brackets — `BEGIN` / `COMMIT` / `ROLLBACK` / `SAVEPOINT`. The
 *     transaction CONTEXT of a statement is carried on the statement itself
 *     (`withinTransaction`), exactly as in the pretend path; the bracket statements
 *     themselves are not rule input.
 *
 * It is a pure classifier — same string in, same verdict out — so the boundary is
 * testable directly, including the case that matters most: the `migrations` table
 * never appears as rule input.
 */
final readonly class ShadowNoiseFilter
{
    /** Leading tokens that mark a statement as session setup or a transaction bracket. */
    private const array CONTEXT_PREFIXES = [
        'SET ',
        'BEGIN',
        'START TRANSACTION',
        'COMMIT',
        'ROLLBACK',
        'SAVEPOINT ',
        'RELEASE SAVEPOINT',
    ];

    /**
     * Whether a captured statement is a real schema change a rule should see, rather
     * than repository bookkeeping, session setup, or a transaction bracket.
     */
    public function isRuleInput(string $sql, string $migrationsTable): bool
    {
        $trimmed = ltrim($sql);
        $upper = strtoupper($trimmed);

        foreach (self::CONTEXT_PREFIXES as $prefix) {
            if (str_starts_with($upper, $prefix)) {
                return false;
            }
        }

        return ! $this->targetsMigrationsTable($trimmed, $migrationsTable);
    }

    /**
     * Whether the statement references the migration repository's table. Laravel
     * always quotes the identifier, so the quoted forms (`"migrations"` on
     * PostgreSQL, `` `migrations` `` on MySQL) are the reliable signal — not a bare
     * word that could be an unrelated column.
     */
    private function targetsMigrationsTable(string $sql, string $migrationsTable): bool
    {
        return array_any(['"'.$migrationsTable.'"', '`'.$migrationsTable.'`'], fn (string $quoted): bool => stripos($sql, $quoted) !== false);
    }
}
