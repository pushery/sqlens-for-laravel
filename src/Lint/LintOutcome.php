<?php

declare(strict_types=1);

namespace Pushery\SQLens\Lint;

use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Capture\SingleFileFailure;
use Pushery\SQLens\Console\ExitCode;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\RunContext;

/**
 * Everything one lint run produced — the aggregate result, the reproducibility
 * header, and the exit code the gate reads — plus the one thing that is NOT a
 * finding: an unsupported engine.
 *
 * An unsupported connection (SQLite, MariaDB) is carried as its own named failure
 * rather than folded into the findings, because it is not a finding ABOUT the
 * migrations — nothing was linted — but a fact about the target. The command shows
 * its message and returns the misconfiguration exit code; the findings list stays
 * empty so the run produces no per-migration noise for an engine it never ran.
 */
final readonly class LintOutcome
{
    public function __construct(
        public Result $result,
        public RunContext $context,
        public ExitCode $exitCode,
        public string $connectionName,
        public ?DriverResolutionFailure $unsupported = null,
        public ?SingleFileFailure $fileFailure = null,
        /**
         * The migration FILES this run resolved as pending, in the order they will be applied.
         *
         * Carried out of the runner so a caller that needs to know WHICH migrations are about to
         * run does not resolve them a second time. Two resolutions are two answers to one question,
         * and the one that drifted would win silently in whichever half read it.
         *
         * From the RESOLVER rather than from the findings, deliberately: a pending migration no
         * rule has anything to say about is still pending, and deriving this from findings would
         * make a clean deploy look like an empty one.
         *
         * @var list<string>
         */
        public array $pendingFiles = [],
        /**
         * The captured statements themselves, in the same form the rules were evaluated against.
         *
         * Objects rather than SQL strings, and that is the whole point: a `CapturedStatement`
         * already carries `canonicalSql`, `statementKind` and `targets`. A caller asking "which
         * tables need an exclusive lock" reads `targets` — the answer this run already produced —
         * instead of parsing the SQL a second time and risking a different one.
         *
         * @var list<CapturedStatement>
         */
        public array $pendingStatements = [],
    ) {}

    /** Whether the run stopped because the target engine is not supported. */
    public function isUnsupported(): bool
    {
        return $this->unsupported instanceof DriverResolutionFailure;
    }
}
