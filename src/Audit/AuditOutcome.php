<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Console\ExitCode;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Lint\LintOutcome;
use Pushery\SQLens\Reporting\RunContext;

/**
 * What one audit run produced — the whole answer, in one value the command hands to a reporter.
 *
 * Deliberately the same shape as {@see LintOutcome}, minus the two fields that
 * are about migration FILES (a single-file fast path has no meaning when the subject is a live
 * schema). Same shape because the command layer's job is identical in both suites — resolve flags,
 * hand the run to a runner, give the result to a reporter, return the exit code — and two shapes
 * would make that job two jobs, which is how the suites start reporting differently.
 */
final readonly class AuditOutcome
{
    public function __construct(
        public Result $result,
        public RunContext $context,
        public ExitCode $exitCode,
        /** The connection the reading was made against — the instance every finding is about. */
        public string $connectionName,
        /**
         * Set when the run stopped because the target engine is not one this package reasons about.
         *
         * Read directly rather than through an `isUnsupported()` predicate: the command needs the
         * failure itself to build its message, so a boolean twin would be a second way to ask one
         * question — and the one nobody called would rot.
         */
        public ?DriverResolutionFailure $unsupported = null,
    ) {}

}
