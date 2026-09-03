<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * What one tool invocation produced: an outcome, an exit code, and the two streams kept apart.
 *
 * The streams stay separate because merging them is unrecoverable. A tool writes its findings
 * to stdout and its complaints to stderr; interleaved, a parser has to guess which line was
 * which, and it will guess wrong on exactly the runs that matter — the ones where something
 * also went sideways.
 *
 * The stderr excerpt is bounded and redacted rather than carried whole. A tool's own output is
 * not automatically safe to show: it may echo the connection string it was handed, and that
 * text can end up in a finding, a report, or a CI log that outlives the run.
 */
final readonly class ToolRunResult
{
    /** No exit code exists when the process never ran; -1 says so rather than pretending 0 or 1. */
    public const int NO_EXIT_CODE = -1;

    public function __construct(
        public ToolRunOutcome $outcome,
        public int $exitCode,
        public string $stdout,
        public string $stderrExcerpt,
    ) {}

    /** A run that produced an exit code — see {@see ToolRunOutcome::produced()} on why not "success". */
    public function produced(): bool
    {
        return $this->outcome->produced();
    }

    /**
     * The deterministic projection — stable key order, so two identical runs serialize identically.
     *
     * @return array{outcome: string, exit_code: int, stderr: string}
     */
    public function toArray(): array
    {
        return [
            'outcome' => $this->outcome->value,
            'exit_code' => $this->exitCode,
            // stdout is deliberately absent: it is the tool's payload, often large, and belongs
            // to whatever parses it — not to a diagnostic projection that lands in a report.
            'stderr' => $this->stderrExcerpt,
        ];
    }
}
