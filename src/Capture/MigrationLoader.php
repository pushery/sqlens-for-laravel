<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Migrations\Migrator;
use Illuminate\Support\Str;
use Pushery\SQLens\Exceptions\UnloadableMigration;
use ReflectionClass;

/**
 * Loads a migration from its file — at most ONCE per file, per run.
 *
 * ## Why this is not just `require`
 *
 * A Laravel 13 migration is an anonymous class, so the file RETURNS the instance and requiring it
 * twice simply produces two of them. A migration written before Laravel 8 is a NAMED class, and
 * requiring THAT file twice is a `Cannot redeclare class` fatal — E_ERROR, uncatchable, the process
 * is gone. Not an exception a captor could turn into a finding: no output, no report, exit 1.
 *
 * That is not hypothetical and it is not only a legacy concern. The moment anything needs a
 * migration's SQL twice in one run — the rollback leg read beside the forward one — the second read
 * is a second load, and on the first named-class migration in the project the whole run dies.
 * Measured, not reasoned about: a bare double `require` of a named-class file terminates PHP with
 * `Cannot redeclare class` and prints nothing through the test runner.
 *
 * ## Two defenses, because neither covers the other's case
 *
 * - **The class-exists shortcut** mirrors {@see Migrator::resolvePath()}:
 *   if the class this file would declare already exists AND was declared from this very file, it is
 *   instantiated instead of being required again. This is what protects a real application, whose
 *   migrations carry Laravel's `Y_m_d_His_name` file names the class name is derived from.
 * - **The per-run memo** catches everything the derivation cannot name — a file whose basename does
 *   not follow the convention, or an anonymous class that would otherwise be re-parsed for nothing.
 *
 * The memo is scoped to this object, and one is built per capture run rather than per process: a
 * cache that outlived the run would hand back an instance of a file that has since been rewritten,
 * which is exactly the sort of quiet wrongness this package exists to prevent.
 */
final class MigrationLoader
{
    /** @var array<string, Migration> */
    private array $loaded = [];

    /**
     * The migration instance for a file.
     *
     * The `require` is what executes the file's top-level code, which is why nothing reaches a
     * loader until the static pre-scan has already judged the file safe.
     */
    public function load(string $file): Migration
    {
        $key = realpath($file) ?: $file;

        if (isset($this->loaded[$key])) {
            $cached = $this->loaded[$key];

            // Same as the framework: a migration with a constructor is required again rather than
            // cloned, because a clone would share whatever its constructor built. A NAMED class
            // never gets here — the class-exists shortcut in resolve() answers it first — so the
            // second require cannot be the redeclare fatal this class exists to prevent.
            return method_exists($cached, '__construct') ? $this->resolve($file) : clone $cached;
        }

        return $this->loaded[$key] = $this->resolve($file);
    }

    /**
     * The instance, from the already-declared class where there is one, else from the file.
     *
     * The shape is the framework's own {@see Migrator::resolvePath()},
     * read off the INSTALLED version rather than recalled — including the part that is easy to miss:
     * a cached instance is CLONED for a migration with no constructor and re-required for one that
     * has one. Cloning keeps two capture legs from sharing mutable state; re-requiring is what a
     * constructor-injected migration needs, and it is safe there because a named class never reaches
     * this branch (the class-exists shortcut above answers first).
     */
    private function resolve(string $file): Migration
    {
        $class = $this->declaredClassFor($file);

        if ($class !== null) {
            return new $class;
        }

        $migration = require $file;

        if ($migration instanceof Migration) {
            return $migration;
        }

        // ⚠️ THE OLD CLASS SHAPE, AND IT ARRIVES HERE AS `int(1)`.
        //
        // `require` returns what the file RETURNS, and 1 when it returns nothing. Both shapes are
        // valid Laravel: the modern one returns an anonymous class, the older one declares a named
        // class and returns nothing. The declared-class shortcut above cannot see the second,
        // because before the `require` the class is not declared yet -- so control lands here with
        // an integer, and a `/** @var Migration */` docblock above it made the return type read as
        // a fact rather than an intention.
        //
        // Measured in a consuming project on 2026-09-05: 24 migrations, exactly ONE in the old
        // shape, and that one aborted the entire run with a TypeError. It came from `vendor:publish`
        // -- a package-published migration, unchanged since -- which is why this is not rare: it is
        // not old project code, it is anybody who ever published one.
        //
        // The second look costs nothing and needs no new derivation: AFTER the require the class IS
        // declared, so the same reflection-checked lookup that answered `null` a moment ago now
        // finds it. Same rule as the framework's own `Migrator::resolve()`.
        $declared = $this->declaredClassFor($file);

        if ($declared !== null) {
            return new $declared;
        }

        throw UnloadableMigration::yieldedNothing($file, get_debug_type($migration));
    }

    /**
     * The migration class this file already declared, or null.
     *
     * The name is derived the way the framework derives it — the file's basename minus Laravel's
     * `Y_m_d_His_` prefix, studly-cased — and the declaring file is then CHECKED by reflection.
     * Without that check a project with an unrelated class of the same name would have it
     * instantiated as a migration.
     *
     * @return class-string<Migration>|null
     */
    private function declaredClassFor(string $file): ?string
    {
        $segments = explode('_', basename($file, '.php'));

        // Laravel's own derivation: the first four segments are the date and time stamp.
        $name = implode('_', array_slice($segments, 4));

        if ($name === '') {
            return null;
        }

        // Str::studly, the framework's own — not a hand-rolled equivalent. The two agree on ASCII
        // and part ways on multibyte input, and a file name is not a place to inherit a subtle
        // difference from the framework whose class name this has to match exactly.
        $class = Str::studly($name);

        if (! class_exists($class) || ! is_subclass_of($class, Migration::class)) {
            return null;
        }

        return new ReflectionClass($class)->getFileName() === (realpath($file) ?: $file) ? $class : null;
    }
}
