<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\Migrations\Migrator;

/**
 * Where this project's migrations live — resolved in ONE place, because two places would disagree.
 *
 * The lint layer needs them to decide what to capture. The capture layer needs them to decide
 * whether a captured statement came from a migration at all — the difference between a password
 * literal that is Critical and the same literal in a seeder, which is test data.
 *
 * Both resolutions were the same three lines, and that is precisely the shape that drifts: the day
 * one of them learns about a new source, the other keeps answering the old way and nothing goes red,
 * because each is internally consistent. The same mistake shipped three times in this package's
 * canonicalizer and fixture lanes, so it is extracted here before it can happen a
 * fourth.
 *
 * ## The order the sources are asked in
 *
 * A project's explicit `sqlens.migration_paths` wins outright when it is set — somebody naming the
 * paths means those and not others, and quietly appending to their list would make the setting
 * advisory.
 *
 * Otherwise the framework's own answer: `databasePath('migrations')` plus every path a package
 * registered on the migrator. `databasePath()` rather than `basePath('database/migrations')`,
 * because they are the same string in a stock application and different the moment one relocates
 * its database directory — and an application that did would have SQLens reading a directory
 * Laravel does not migrate from, reporting clean while never having looked at the migrations that
 * actually run.
 */
final readonly class MigrationPaths
{
    public function __construct(
        private Application $app,
        private Migrator $migrator,
        private Repository $config,
    ) {}

    /**
     * The paths this run treats as migration paths.
     *
     * @return list<string>
     */
    public function all(): array
    {
        return $this->configured() ?? $this->fromFramework();
    }

    /**
     * The project's explicit list, or null when it made none.
     *
     * Null rather than an empty array, and the distinction is load-bearing: an empty list is a
     * project saying "no migration paths", which is a legitimate if unusual answer, while null is
     * "did not say" and falls through to the framework. Collapsing them would make a deliberate
     * empty list silently mean the opposite of what it says.
     *
     * @return list<string>|null
     */
    private function configured(): ?array
    {
        $configured = $this->config->get('sqlens.migration_paths');

        if (! is_array($configured)) {
            return null;
        }

        $paths = array_values(array_filter($configured, is_string(...)));

        return $paths === [] ? null : $paths;
    }

    /** @return list<string> */
    private function fromFramework(): array
    {
        return [$this->app->databasePath('migrations'), ...array_values($this->migrator->paths())];
    }
}
