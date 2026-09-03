<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use Illuminate\Contracts\Config\Repository;

/**
 * The baseline a run suppresses against, read from `sqlens.baseline.path`.
 *
 * ## One reader, because the file has one meaning
 *
 * Both suites accept the same baseline, from the same key, in the same format — and that is a
 * decision, not an accident: a project's accepted debt is one list, and a second loader would
 * eventually disagree with the first about what a missing file, an unreadable file or a relative
 * path means. Two answers to "is this finding baselined?" is one answer too many.
 *
 * The `sqlens:baseline` command writes through {@see BaselineSerializer} directly rather than
 * through this class, because writing is a different question: it knows the path it was given,
 * and it must fail loudly on a directory it cannot create.
 *
 * ## A broken baseline is not applied, and that is the safe direction
 *
 * A file that cannot be read or cannot be parsed yields an EMPTY baseline: the findings it would
 * have accepted stay visible. The opposite reading — treat an unparsable file as "everything is
 * accepted" — would turn a corrupted byte into a clean report over a database with known problems,
 * which is the silent green this package is built to refuse.
 */
final readonly class ConfiguredBaseline
{
    public function __construct(private Repository $config) {}

    /**
     * The configured baseline, or an empty one when none is set, missing, or unreadable.
     *
     * Deliberately NOT aware of `--ignore-baseline`. This answers "what does the project have",
     * and applying it is the caller's decision — two different questions that must stay apart,
     * because a run using the bypass still needs to know whether there was anything to bypass. An
     * earlier draft folded the switch in here, and the report then told a project with a real
     * baseline that its emergency exit had opened nothing.
     */
    public function forRun(): BaselineFile
    {
        $path = $this->config->get('sqlens.baseline.path');

        if (! is_string($path) || $path === '' || ! is_file($path)) {
            return BaselineFile::of([]);
        }

        // The failure PROPAGATES. It used to be swallowed into an empty baseline, and that was the
        // quiet kind of wrong: every accepted finding came back at once, the reader saw a wall of
        // new findings, and nothing in the report said the file could not be read. Worse with
        // `--update`, which would then rewrite the file from the current run and discard the
        // project's accepted entries for good.
        //
        // A baseline that cannot be read is a misconfiguration, and the command turns it into the
        // misconfiguration exit with the reason named — the same treatment an unparseable config
        // gets, for the same reason.
        return new BaselineSerializer()->deserialize((string) file_get_contents($path), $path);
    }
}
