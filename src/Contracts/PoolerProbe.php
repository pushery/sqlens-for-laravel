<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * Answers, HEURISTICALLY, whether a connection sits behind a transaction pooler
 * (PgBouncer in transaction mode) — the one topology where the shadow mode's
 * template operations cannot run.
 *
 * This is explicitly a heuristic and is named one everywhere it surfaces: a
 * pooler is deliberately transparent, so there is no authoritative "are you a
 * pooler?" question to ask. The probe looks for the tells (a backend pid that
 * changes between two statements, because transaction pooling hands each
 * statement a different server connection) and reports a best guess. The finding
 * it drives says "detected" with that uncertainty, never a false certainty.
 *
 * The check is a read — it runs a status query and nothing more. When it is
 * unsure, it errs toward reporting NOT pooled, because a false positive would
 * block a perfectly good direct connection; the cost of a false negative (a
 * template operation that then fails) is a clear error the user can act on.
 */
interface PoolerProbe
{
    /**
     * Whether the named connection appears to be transaction-pooled. Runs its
     * heuristic status queries against that connection.
     */
    public function isTransactionPooled(string $connectionName): bool;
}
