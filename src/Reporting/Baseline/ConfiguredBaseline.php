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
    /**
     * @param  string  $projectRoot  what `sqlens.baseline.path` is relative TO
     */
    public function __construct(private Repository $config, private string $projectRoot) {}

    /**
     * Whether a baseline is CONFIGURED and the file it names is not there.
     *
     * ⚠️ Distinct from "no baseline", and that distinction is the whole reason this exists. Both
     * produce an empty `BaselineFile`, and from the report they are indistinguishable — one is a
     * project that accepts nothing, the other is a project whose accepted findings have all come
     * back at once because a path does not resolve. A reader seeing a wall of new findings has no
     * way to tell which happened.
     *
     * NOT an error: `sqlens:baseline` has to be runnable before the file exists, which is how a
     * project creates one in the first place. So it is a notice, in the same family as an
     * unreadable debt ledger — the run continues and says what it could not find.
     */
    public function configuredButAbsent(): bool
    {
        $path = $this->config->get('sqlens.baseline.path');

        return is_string($path) && $path !== '' && ! is_file(self::anchored($path, $this->projectRoot));
    }

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

        if (! is_string($path) || $path === '') {
            return BaselineFile::of([]);
        }

        // ⚠️ ANCHORED AT THE PROJECT ROOT, not at the process's working directory. The config
        // promises a repo-relative path and the schema refuses an absolute one, so a bare
        // `is_file()` asked a question about wherever the process happened to be started:
        // the monorepo root under `php path/to/artisan`, whatever a deploy script last `cd`-ed to,
        // `public/` under `Artisan::call()` from a request.
        //
        // The three sibling keys with the same promise — the debt ledger in both runners and the
        // agent's findings path — were already anchored. Only this one was not, and it fails in
        // the quiet direction: the file is not found, the baseline reads as empty, and every
        // accepted finding comes back at once with nothing in the report saying a baseline was
        // configured.
        $absolute = self::anchored($path, $this->projectRoot);

        if (! is_file($absolute)) {
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
        // The RELATIVE path travels into the message: it is what the project wrote in its config
        // and what a reader can act on.
        return new BaselineSerializer()->deserialize((string) file_get_contents($absolute), $path);
    }

    /**
     * A configured path, resolved against the root it is documented to be relative to.
     *
     * ⚠️ An ABSOLUTE path is left alone. The schema refuses one, so a project cannot configure it
     * on purpose — but a configuration that slips past a validator must not then be read from a
     * third place nobody named. Prefixing a root onto `/var/lib/…` produces a path that exists
     * nowhere, which is the silent failure this whole change is about, one level down.
     */
    public static function anchored(string $path, string $projectRoot): string
    {
        return str_starts_with($path, '/') ? $path : $projectRoot.'/'.$path;
    }
}
