<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * The seam between a caller and the predeploy run it drives — the deploy half's `LintRuns`.
 *
 * ## Why it was extracted
 *
 * The composition lived inside `PredeployCommand::handle()`: resolve the connection, open a bounded
 * preflight session, lint the pending migrations through the same entry point `sqlens:lint` uses,
 * build the context, run the checks, read the session bounds back. Eight services, in an order that
 * matters.
 *
 * That was fine while one caller existed. The moment a second one needed the same verdict — the MCP
 * `predeploy` tool — the private method became a specification only one caller could read, and a
 * second composition would have been a second predeploy: same name, same promise, its own answer
 * about whether a deploy may proceed. The whole agent layer exists not to be that.
 *
 * So the composition moved here and the command became a consumer of it, exactly as `LintRunner`
 * became `LintRuns` when the security run needed to call both halves.
 *
 * ## What stays with the caller
 *
 * Reporting and the exit code. The command turns an outcome into a report and one of four numbers;
 * the tool turns the same outcome into a three-valued answer. Neither decision belongs to a service
 * that knows nothing about who asked.
 */
interface PreflightRuns
{
    /**
     * Check the target database immediately before a deploy — read-only, bounded, fail-closed.
     *
     * @param  string|null  $connection  a connection NAME, or null for the resolved preflight connection
     * @param  string|null  $profile  the environment profile; null means `predeploy`, the paranoid one
     * @param  int|null  $budgetMs  the whole run's time budget; null means the configured one
     */
    public function run(?string $connection = null, ?string $profile = null, ?int $budgetMs = null): PreflightOutcome;
}
