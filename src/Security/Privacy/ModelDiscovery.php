<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use FilesystemIterator;
use Illuminate\Database\Eloquent\Model;
use Pushery\SQLens\Capture\MigrationLoader;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use ReflectionClass;
use SplFileInfo;
use Throwable;

/**
 * The Eloquent models of the host application, so a column can be asked what it is cast to.
 *
 * ## Why this exists at all
 *
 * {@see ModelCastReader} answers "is this column encrypted" from a model's casts, and it is handed a
 * LIST of model classes. Nothing in this package produced that list, so the rule that needs it would
 * have reported every single column as `undetermined` — a rule that runs cleanly and never says
 * anything, which is the most expensive kind of green there is.
 *
 * ## It is HANDED its root and namespace, and does not go looking
 *
 * Both come from the service provider, which is the one place that has the application. Reaching for
 * a container here would mean guarding against a host that is not a full Laravel install — and the
 * guard could never be exercised, because the container's own type says the method is always there.
 * A check that cannot fail is a check that documents a worry rather than answering it.
 *
 * ## The convention is Laravel's, not one invented here
 *
 * `model:prune` answers the same question by looking in `app/Models` and falling back to `app/`.
 * That is where a Laravel developer puts models and where they expect a tool to look, so this
 * follows it rather than inventing a config key nobody would know to set.
 *
 * ## Derived, then CHECKED
 *
 * A class name is derived from the path — the application namespace plus the directories below the
 * scanned root — and then verified by reflection: the class must exist, be a concrete `Model`, and
 * be DECLARED IN THE FILE the name came from. The same discipline {@see MigrationLoader}
 * applies, and for the same reason: a project whose autoloader maps a different file to that name
 * would otherwise have an unrelated class constructed as one of its models.
 *
 * ## An empty answer is a reason, not a pass — and one failure is deliberately loud
 *
 * A host application with no models, a subdirectory the process may not enter, an autoloader that
 * refuses a single class: each ends as an EMPTY list or a skipped file, and the caller turns an
 * empty list into a named `undetermined`. Discovery finding nothing is a reason a question could not
 * be answered, never an answer to it.
 *
 * The one exception is an application directory that exists and cannot be OPENED. That propagates,
 * because reporting "no models" for a broken installation would make a privacy report look clean
 * when nothing was examined at all.
 */
final readonly class ModelDiscovery
{
    /**
     * @param  string  $root  the directory the application keeps its classes in
     * @param  string  $namespace  the namespace that root maps to, trailing separator included
     */
    public function __construct(private string $root, private string $namespace) {}

    /**
     * Every concrete Eloquent model under the root, sorted.
     *
     * Sorted because the reading built from it is compared against a golden file and reported to a
     * user: a list that followed the filesystem's order would differ between a developer's machine
     * and CI over a schema nobody touched.
     *
     * @return list<class-string<Model>>
     */
    public function models(): array
    {
        $directory = $this->scannedDirectory();

        if ($directory === null) {
            return [];
        }

        $models = [];

        foreach ($this->phpFilesIn($directory) as $file) {
            $class = $this->declaredModelFor($directory, $file);

            if ($class !== null) {
                $models[] = $class;
            }
        }

        sort($models);

        return array_values(array_unique($models));
    }

    /**
     * `app/Models` when it exists, otherwise `app` — Laravel's own order, and it matters.
     *
     * An application predating the `Models` directory keeps them directly under `app`, and one that
     * has the directory keeps nothing else in it. Scanning the fallback FIRST would walk an entire
     * application's classes to find models that are all in one place.
     */
    private function scannedDirectory(): ?string
    {
        if ($this->root === '') {
            return null;
        }

        $nested = $this->root.DIRECTORY_SEPARATOR.'Models';

        if (is_dir($nested)) {
            return $nested;
        }

        return is_dir($this->root) ? $this->root : null;
    }

    /**
     * @return list<SplFileInfo>
     */
    private function phpFilesIn(string $directory): array
    {
        // `CATCH_GET_CHILD` rather than a try/catch around the construction, and the difference is
        // which failure is REAL. A subdirectory the process may not enter is an ordinary thing to
        // meet in somebody's application, and the flag skips it — no branch, no catch, nothing to
        // leave untested.
        //
        // The ROOT being unopenable is the other case, and it deliberately propagates: the caller
        // has already established it is a directory, so the only way to get here is an installation
        // whose `app/` cannot be read. Swallowing that into "no models found" would turn a broken
        // install into a clean-looking privacy report, which is the one answer this package must
        // never produce by accident. {@see PrivacyDictionary} throws for the same reason.
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY,
            RecursiveIteratorIterator::CATCH_GET_CHILD,
        );

        $files = [];

        foreach ($iterator as $file) {
            if ($file instanceof SplFileInfo && $file->isFile() && $file->getExtension() === 'php') {
                $files[] = $file;
            }
        }

        return $files;
    }

    /**
     * The model class this file declares, or null.
     *
     * @return class-string<Model>|null
     */
    private function declaredModelFor(string $directory, SplFileInfo $file): ?string
    {
        $path = $file->getPathname();

        $relative = mb_substr($path, mb_strlen($directory) + 1, -4);

        // `app/Models/Billing/Invoice.php` under namespace `App\` is `App\Models\Billing\Invoice`
        // when Models is the scanned root, so the segment is re-attached rather than assumed away.
        $suffix = str_replace(DIRECTORY_SEPARATOR, '\\', $relative);

        $class = $this->namespace.(str_ends_with($directory, DIRECTORY_SEPARATOR.'Models') ? 'Models\\' : '').$suffix;

        try {
            if (! class_exists($class) || ! is_subclass_of($class, Model::class)) {
                return null;
            }

            $reflection = new ReflectionClass($class);
        } catch (Throwable) {
            // An autoloader that throws while resolving one file must not take the whole discovery
            // with it — the other models are still worth having.
            return null;
        }

        if ($reflection->isAbstract()) {
            return null;
        }

        // The check the derivation cannot make on its own: a project whose autoloader maps this name
        // somewhere else would otherwise have an unrelated class treated as one of its models.
        return $reflection->getFileName() === (realpath($path) ?: $path) ? $class : null;
    }
}
