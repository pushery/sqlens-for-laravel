<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Deploy\DebtMode;

/**
 * The seam between the `sqlens:audit` command and the run it drives.
 *
 * An interface rather than a class, and the reason is the command's own test: the exit-code
 * contract has four outcomes (clean, findings over the gate, misconfiguration, undetermined under
 * strict) and each needs a test that pins the exact code. Driving those through a real reading
 * would mean building four database states to exercise four `return` statements — slow, fragile,
 * and testing the reader rather than the contract.
 *
 * It is also what keeps the command honest about its own scope: it holds no SQL and no driver
 * branch, so the only thing it CAN do is resolve flags, call this, and translate the answer into an
 * exit code. A command that could reach a catalog directly would eventually do so.
 */
interface AuditRuns
{
    /**
     * Audit one connection's live schema.
     *
     * @param  string|null  $connection  the connection name, or null for the configured default
     * @param  string|null  $host  the ONE read host to address, when the connection configures a
     *                             choice. Null leaves it to the configuration — which refuses the
     *                             run rather than choosing, when more than one is offered.
     * @param  int|null  $level  the cumulative strictness level, or null to take the configured one
     * @param  list<string>|null  $categories  the categories to scope to, or null for the configured set
     * @param  bool|null  $strictUndetermined  override the configured strict_undetermined, or null to keep it
     * @param  bool|null  $strictTools  override the configured strict_tools, or null to keep it. Trailing and
     *                                  defaulted on purpose: every existing call site passes its arguments by
     *                                  name, so adding it here changes no caller and breaks no implementer.
     */
    public function run(
        ?string $connection = null,
        ?string $host = null,
        ?int $level = null,
        ?array $categories = null,
        ?bool $strictUndetermined = null,
        bool $ignoreBaseline = false,
        ?bool $strictTools = null,
        DebtMode $debt = DebtMode::Check,
    ): AuditOutcome;
}
