<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Illuminate\Contracts\Config\Repository;

/**
 * Which files a format run is allowed to find — the discovery half of `sqlens.format`.
 *
 * ## This is a SAFETY surface, not a convenience one
 *
 * `format` is the only suite in this package that writes. The set of candidate files is therefore
 * the blast radius, and every rule below is written from that side: the defaults are narrow, the
 * two dangerous widenings are refused rather than warned about, and nothing here is discovered by
 * walking somewhere the configuration did not name.
 *
 * ## Three keys, and why `include` is not a fourth
 *
 * `paths`, `exclude` and `extensions`. An `include` glob was specified alongside them and is
 * deliberately absent: `paths` says where to look and `extensions` says what counts, so `include`
 * would be a third way to answer the same question — and its interaction with `exclude` is a
 * precedence rule nobody would remember correctly at the moment it mattered. A project that needs
 * one directory takes it as a root.
 *
 * ## The reserved extensions are refused TWICE, on purpose
 *
 * The config validator reports `format.extensions: ['php']` as out of range, and this class drops
 * it again at runtime. That is not the redundant belt this repository usually argues against: the
 * two guards sit on different paths. Validation runs when somebody asks for it; a format run
 * happens whenever somebody types the command, and the failure mode here is a destroyed migration
 * rather than a wrong report. A `.php` file read as SQL is rewritten as though the whole file were
 * one statement, and the run calls that `reformatted`.
 */
final readonly class FormatDiscovery
{
    /**
     * Directory names a run never descends INTO, whatever the configuration says.
     *
     * Not configurable, because there is no project for which walking into `vendor/` is the right
     * answer — a run that did would rewrite files the next `composer install` overwrites, after
     * committing them.
     *
     * ⚠️ "Descends into", not "appears anywhere in the path", and the distinction is measured. The
     * first draft rejected any path with one of these as a segment, which is the same rule stated
     * over the absolute path — and it rejected a legitimate root, because a Testbench application's
     * own `database/migrations` lives under `vendor/orchestra/testbench-core/`. The fallback arm
     * went red over a correct configuration. A root somebody NAMES is a root; the rule is about
     * where a walk wanders, so it is applied by {@see mayDescend()} during the walk and nowhere
     * else.
     */
    public const array NEVER_DESCEND = ['vendor', 'node_modules', 'storage'];

    /**
     * Extensions a project cannot add, because the file they name is a PROGRAM that contains SQL.
     *
     * See the class docblock. This is the one widening that destroys data rather than producing a
     * bad report, which is why it is a refusal and not a warning.
     */
    public const array RESERVED_EXTENSIONS = ['php', 'phtml'];

    /** @var list<string> */
    public const array DEFAULT_EXTENSIONS = ['sql'];

    /**
     * `schema:dump` writes `database/schema/*.sql` from the database, in whatever shape the dumper
     * produces. Reformatting one makes the next dump a large diff against a file nobody edits, and
     * a project sees that diff on every deploy.
     *
     * It is a DEFAULT rather than a hard rule, which is the difference from `NEVER_DESCEND` above:
     * a project that hand-maintains its schema file can take the entry out, and the run then names
     * the dump files it touched so the opt-in is visible in the output rather than only in a config
     * file nobody reads during a review.
     *
     * @var list<string>
     */
    public const array DEFAULT_EXCLUDE = ['database/schema/*'];

    /**
     * @param  list<string>  $roots  where to look; empty means "the application's migration paths"
     * @param  list<string>  $exclude  globs, matched against the walked path — see {@see admits()}
     * @param  list<string>  $extensions  without the dot, lowercase
     */
    public function __construct(
        public array $roots = [],
        public array $exclude = self::DEFAULT_EXCLUDE,
        public array $extensions = self::DEFAULT_EXTENSIONS,
    ) {}

    public static function defaults(): self
    {
        return new self;
    }

    public static function from(Repository $config): self
    {
        return new self(
            roots: self::strings($config->get('sqlens.format.paths'), []),
            exclude: self::strings($config->get('sqlens.format.exclude'), self::DEFAULT_EXCLUDE),
            // Reserved names are dropped here rather than refused, because a run must still HAPPEN
            // over a misconfigured project — refusing outright would turn one bad list entry into a
            // command nobody can use, and the validator is where a configuration is judged.
            //
            // Cleaned HERE so the field others read is honest, and cleaned AGAIN in `admits()` so
            // the decision is safe however the object was built. Two filters, two jobs: this one is
            // about what the run REPORTS about itself, that one about what it TOUCHES.
            extensions: self::formattable(self::strings($config->get('sqlens.format.extensions'), self::DEFAULT_EXTENSIONS)),
        );
    }

    /** Whether this file is one this run may format. */
    public function admits(string $path): bool
    {
        $normalized = strtolower(str_replace('\\', '/', $path));

        // ⚠️ NOT IN SCOPE is a different answer from SKIPPED. A `.php`, `.md` or `.json` file in a
        // formatted directory is not a file this suite could not handle — it is a file this suite
        // has nothing to do with, and reporting it as `undetermined` would fill every run with
        // entries nobody can act on. A skip carries a reason because somebody might fix it; this
        // carries none because there is nothing to fix.
        if (! array_any(self::formattable($this->extensions), static fn (string $extension): bool => str_ends_with($normalized, '.'.strtolower($extension)))) {
            return false;
        }

        return ! array_any($this->exclude, fn (string $glob): bool => $this->matches($glob, $normalized));
    }

    /** Whether a run may walk into this directory. Pruning here is what "never descend" means. */
    public function mayDescend(string $path): bool
    {
        return ! in_array(strtolower(basename($path)), self::NEVER_DESCEND, true);
    }

    /**
     * A glob is matched against the walked path, and a repo-relative one is anchored for you.
     *
     * The scanner walks ABSOLUTE paths; a project writes `database/schema/*`, which matches none of
     * them. So a glob that names neither an absolute path nor a wildcard start is also tried with a
     * `*​/` in front. One rule, both directions, rather than a config key that asks somebody to
     * know which form the scanner happens to hold.
     *
     * PHP's `fnmatch()` without `FNM_PATHNAME` lets `*` cross a `/`, which is what makes the
     * anchored form reach a path of any depth.
     */
    private function matches(string $glob, string $normalized): bool
    {
        $glob = strtolower(str_replace('\\', '/', $glob));

        return fnmatch($glob, $normalized) || fnmatch('*/'.ltrim($glob, '/'), $normalized);
    }

    /**
     * The extensions of a list that a format run may actually take.
     *
     * Falls back to the default when nothing survives — which happens both for `extensions: []` and
     * for a list holding only reserved names. The validator refuses the first, so this is the second
     * line rather than the first; the alternative is a run that finds nothing and reports a clean
     * tree, which is the one answer a formatter must not give when it looked at no files.
     *
     * @param  list<string>  $extensions
     * @return list<string>
     */
    private static function formattable(array $extensions): array
    {
        $taken = array_values(array_filter(
            $extensions,
            static fn (string $extension): bool => ! in_array(strtolower($extension), self::RESERVED_EXTENSIONS, true),
        ));

        return $taken === [] ? self::DEFAULT_EXTENSIONS : $taken;
    }

    /**
     * @param  list<string>  $default
     * @return list<string>
     */
    private static function strings(mixed $value, array $default): array
    {
        if (! is_array($value)) {
            return $default;
        }

        return array_values(array_filter(
            array_filter($value, is_string(...)),
            static fn (string $item): bool => $item !== '',
        ));
    }
}
