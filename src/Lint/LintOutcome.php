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
         * WHICH `--file` failed to resolve.
         *
         * It became necessary the moment the option accepted several: the failure is an enum and
         * cannot carry the path, so a run over four files that refused one of them could name the
         * reason and not the file. Naming the wrong half of that is worse than naming neither —
         * the reader checks the first file in the list and finds nothing wrong with it.
         */
        public ?string $fileFailurePath = null,
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
        /**
         * Whether {@see self::$pendingStatements} holds everything the deploy will run.
         *
         * True only when every pending migration's `up()` was captured. A migration the capture could
         * not determine contributes no statements, and a caller asking "does any statement do X"
         * would read its absence as a no.
         */
        public bool $pendingStatementsComplete = false,
        /**
         * Whether the run read the migrations it was pointed at and judged them.
         *
         * The misconfiguration exit does not say the run looked at nothing: under
         * `sqlens.baseline.stale = error` a run that judged every migration ends on it too. A
         * caller that reads the exit code as "nothing was checked" asks this first. False unless
         * the run got that far, so an outcome built anywhere else keeps meaning one that did not.
         */
        public bool $examined = false,
        /**
         * Whether it was the baseline that ended this run on a misconfiguration: entries that
         * matched nothing, under `sqlens.baseline.stale = error`.
         *
         * Said on its own rather than inferred from the exit code and {@see self::$examined}, so a
         * caller that has to name the cause does not guess it.
         */
        public bool $staleBaselineBreaks = false,
        /**
         * The migrations the project has that this run did not read, by name.
         *
         * Every one that already ran on this database, and over `--file` every one it was not
         * given. The baseline entries about them are not this run's to judge, and a baseline this
         * run writes has to keep them rather than drop what it never looked at.
         *
         * @var list<string>
         */
        public array $unreadMigrations = [],
    ) {}

    /**
     * What the exit code means for this run, in a sentence.
     *
     * The misconfiguration exit's own description says nothing was audited. That is the refusal,
     * and it is false for a run the stale baseline ended after judging every migration it read.
     */
    public function gateMeaning(): string
    {
        return $this->staleBaselineBreaks
            ? 'Baseline entries matched nothing and sqlens.baseline.stale is error, so the baseline counts as misconfigured. The migrations were judged, and the stale entries are in the report.'
            : $this->exitCode->description();
    }

    /** Whether the run stopped because the target engine is not supported. */
    public function isUnsupported(): bool
    {
        return $this->unsupported instanceof DriverResolutionFailure;
    }
}
