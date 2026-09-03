<?php

declare(strict_types=1);

namespace Pushery\SQLens\Lint;

use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Deploy\DebtMode;
use Pushery\SQLens\Subjects\CaptureMode;

/**
 * The seam between a caller and the lint run it drives.
 *
 * The audit half has had one since it was written, for a reason its own docblock states: driving a
 * command's four exit codes through a real reading means building four database states to exercise
 * four `return` statements. The lint half never got one, and the asymmetry only became a problem
 * when something needed to CALL both — the security run aggregates them, and `LintRunner` is `final
 * readonly` with no contract, so half of that aggregation could not be tested at all.
 *
 * Extracted rather than invented: the signature below is the runner's, unchanged. What is new is
 * only that a caller may depend on the shape instead of the class.
 */
interface LintRuns
{
    /**
     * Run the lint suite over a connection, or the resolved default, capturing the pending
     * migrations found under the given paths.
     *
     * @param  list<string>|null  $migrationPaths  null means the application's registered paths
     * @param  list<string>|null  $categories  category values to scope to (null = the config's, empty = all)
     * @param  bool  $applyBaseline  whether to suppress against the configured baseline
     */
    public function run(
        ?string $connection,
        ?array $migrationPaths,
        CaptureMode $mode,
        ?string $assumeServerVersion = null,
        ?int $level = null,
        ?array $categories = null,
        bool $applyBaseline = true,
        ?bool $strictTools = null,
        ?string $file = null,
        ?GuardDecision $guard = null,
        bool $roundtrip = false,
        /**
         * What this run may do with the debt account. Null means the caller did not ask, which is
         * NOT the same as `check`: a caller that never heard of the account gets no debt pass at
         * all, so adding this parameter changed no existing behavior.
         */
        ?DebtMode $debt = null,
    ): LintOutcome;
}
