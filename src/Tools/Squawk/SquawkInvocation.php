<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

/**
 * The knobs one Squawk run is given, gathered so the runner never reads configuration itself.
 *
 * Every value here changes the answer, and the two that are nullable are nullable because
 * "SQLens does not know" and "SQLens says no" are different instructions. A server version we
 * could not establish must not be passed as a guess: the version is load-bearing — the same
 * migration measured four findings at one server version and three at another — so guessing it
 * would quietly produce a different verdict than the one SQLens itself reasons about.
 */
final readonly class SquawkInvocation
{
    /**
     * @param  string  $reportedPath  the path findings are reported under. The migration's own
     *                                path, not a temp file: it goes into the tool's output
     *                                verbatim, and a real file path would put a machine-specific
     *                                absolute path into a report that has to read the same in CI.
     * @param  string|null  $pgVersion  the assumed server version to pass through, or null when it
     *                                  is not established. The tool accepts ANY string here without
     *                                  complaint — `999.0` was measured as accepted — so validating
     *                                  it is this side's job, not something the run will surface.
     * @param  bool|null  $insideTransaction  whether the statements run inside a transaction, or
     *                                        null to leave the tool's own assumption alone.
     * @param  float  $timeoutSeconds  the bound one invocation gets before it is reported as
     *                                 timed out. An amplifier that hangs must cost a named
     *                                 undetermined, never the lint run it was helping.
     */
    public function __construct(
        public string $reportedPath,
        public ?string $pgVersion = null,
        public ?bool $insideTransaction = null,
        public float $timeoutSeconds = 10.0,
    ) {}
}
