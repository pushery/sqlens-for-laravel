<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Pushery\SQLens\Api\ApiSurface;
use Pushery\SQLens\Api\BreakingChangeDetector;
use Pushery\SQLens\Api\SurfaceChange;
use Pushery\SQLens\Catalog\RuleRegistryExport;

/**
 * Rewrites the machine-readable API surface from the shipped registry.
 *
 * ## Hand maintenance is the enemy, and this command is the answer to it
 *
 * A snapshot somebody edits by hand drifts from the code, and a breaking-change gate reading a
 * drifted snapshot reports whatever the last editor believed. The file is therefore GENERATED, the
 * generator is one command, and a test compares the checked-in file against a fresh generation —
 * so a stale snapshot is a red build rather than a quiet wrong answer.
 *
 * ## Not part of the promised command surface
 *
 * From 1.0 the `sqlens:*` commands are public API, and registration is what makes a command part of
 * that promise. This one rewrites a file inside the package's own repository and would do nothing
 * useful in a consuming application, so it is registered only by the development provider, which
 * nothing auto-discovers. A test boots an ordinary application and asserts the name is absent.
 */
final class ApiSnapshotCommand extends Command
{
    /** Repo-relative, and the same path the drift test reads. */
    public const string SNAPSHOT = 'resources/data/api-surface.json';

    protected $signature = 'sqlens:api-snapshot
        {--check : Report drift instead of writing}
        {--path= : Where to write, repo-relative. Defaults to the shipped snapshot}
        {--against= : A released snapshot to classify this one against, repo-relative}';

    protected $description = 'Rewrite the machine-readable API surface snapshot (development only)';

    public function handle(): int
    {
        $root = dirname(__DIR__, 2);

        /** @var array{entries?: list<array<string, mixed>>} $registry */
        $registry = json_decode(
            (string) file_get_contents($root.'/'.RuleRegistryExport::BUNDLED_FILE),
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        $rendered = $this->render(ApiSurface::of($registry));

        // A parameter rather than a constant reach, and the reason is a defect this repository
        // has paid for before: a test that writes to a real repository path destroys work and stays
        // green while doing it. With the path injectable, every arm below writes into a temp file
        // and the shipped snapshot is only ever touched by somebody running the command on purpose.
        $relative = $this->option('path');
        $path = $root.'/'.(is_string($relative) && $relative !== '' ? $relative : self::SNAPSHOT);
        $current = is_file($path) ? (string) file_get_contents($path) : null;

        $against = $this->option('against');

        if (is_string($against) && $against !== '') {
            return $this->classifyAgainst($root.'/'.$against, ApiSurface::of($registry));
        }

        if ($this->option('check')) {
            // The gate's form. It reports rather than repairs, because a command that silently
            // fixed the file it is checking would make the check unable to fail.
            if ($current === $rendered) {
                $this->components->info('The API surface snapshot matches the code.');

                return self::SUCCESS;
            }

            $this->components->error(sprintf(
                'The API surface snapshot is stale. Run `sqlens:api-snapshot` and read the diff: it '
                .'is the contract change. %s',
                $current === null ? 'The file does not exist yet.' : 'The checked-in file differs from the generated one.',
            ));

            return self::FAILURE;
        }

        file_put_contents($path, $rendered);

        $this->components->info($current === $rendered
            ? 'The API surface snapshot was already current.'
            : 'The API surface snapshot was rewritten — read the diff, it is the contract change.');

        return self::SUCCESS;
    }

    /**
     * Classify this surface against one that shipped.
     *
     * ## Why the comparison is a separate mode rather than part of `--check`
     *
     * `--check` asks "is the checked-in file current" — a question about THIS commit, answerable
     * without any history. This asks "what would releasing it cost", which needs a released
     * baseline and belongs to the release path.
     *
     * Folding them together would mean every ordinary run needed a baseline it does not have, and
     * the usual answer to a check that cannot run is to stop running it.
     *
     * @param  array<string, mixed>  $candidate
     */
    private function classifyAgainst(string $releasedPath, array $candidate): int
    {
        if (! is_file($releasedPath)) {
            // Named rather than treated as "no changes". A missing baseline compared against
            // silently would report a clean diff — the most reassuring possible output for the
            // state where nothing was compared at all.
            $this->components->error(sprintf(
                'No released snapshot at `%s`, so there is nothing to classify against. A missing '
                .'baseline is not a clean diff.',
                $releasedPath,
            ));

            return self::FAILURE;
        }

        /** @var array<string, mixed> $released */
        $released = json_decode((string) file_get_contents($releasedPath), true, flags: JSON_THROW_ON_ERROR);

        $changes = BreakingChangeDetector::compare($released, $candidate);
        $blocking = BreakingChangeDetector::blocking($changes);

        foreach ($changes as $change) {
            // Every change is printed, not only the blocking ones. A maintainer reading this is
            // deciding what KIND of release to cut, and the permitted changes are half that answer.
            $change->class->blocksMinorRelease()
                ? $this->components->warn($change->describe())
                : $this->components->info($change->describe());
        }

        if ($blocking !== []) {
            $this->components->error(sprintf(
                '%d change(s) may only ship in a MAJOR release:%s%s',
                count($blocking),
                PHP_EOL.'  - ',
                implode(PHP_EOL.'  - ', array_map(static fn (SurfaceChange $c): string => $c->describe(), $blocking)),
            ));

            return self::FAILURE;
        }

        $this->components->info(sprintf('%d change(s), none of them breaking.', count($changes)));

        return self::SUCCESS;
    }

    /**
     * The snapshot as bytes.
     *
     * Pretty-printed with unescaped slashes and a trailing newline. The file is committed and its
     * DIFF is the deliverable — `JSON_PRETTY_PRINT` alone would escape every slash in a
     * documentation url and turn a readable line into noise.
     *
     * @param  array<string, mixed>  $surface
     */
    private function render(array $surface): string
    {
        return json_encode($surface, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n";
    }
}
