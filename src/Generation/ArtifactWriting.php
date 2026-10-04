<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use Illuminate\Filesystem\Filesystem;

/**
 * How a generated artifact reaches the disk — decided once, here.
 *
 * Line endings, the trailing newline and the file mode are part of a generated file's IDENTITY,
 * not incidental to it: `sqlens:agent-rules --check` compares bytes, so a second renderer that
 * chose `PHP_EOL` would turn a Windows checkout red for nobody's fault, and a third that let the
 * mode fall out of the writer's umask would produce a file that differs between a developer's
 * machine and CI without a single byte of content changing.
 *
 * ## Why the write is here rather than in the renderers
 *
 * A renderer returns text. It never touches a filesystem, and the exporter does not either — the
 * only code that writes is the command, behind its `--check` branch. That is what makes `--check`
 * and writing the same code path with one branch at the end, instead of two paths that agree until
 * they do not. "Cannot write" is worth more than "should not write".
 *
 * ## Everything below was measured, and two of the three are surprises
 *
 * Against `laravel/framework v13.23.0`, the version installed here. The full readings are
 * recorded with this package's development notes; the three that shaped this class are below.
 *
 * - `Filesystem::replace()` is atomic (tempnam + rename), which `put()` is not.
 * - With no mode it chmods to `0777 - umask()`, so at the ordinary `umask 0022` it produces
 *   **`0755` — an executable markdown file**. So the mode is passed explicitly, always.
 * - A missing target directory makes `replace()` fail **silently**: `rename()` emits a warning and
 *   no file appears. That is why the directory is ensured before every write rather than assumed;
 *   a run reporting success over a file that does not exist is the exact failure this package
 *   refuses everywhere else.
 */
final readonly class ArtifactWriting
{
    /**
     * The only line ending a generated artifact may contain.
     *
     * Never `PHP_EOL`. The artifact is compared byte for byte by `--check`, so a platform-dependent
     * separator would make the same snapshot produce two different files.
     */
    public const string LINE_ENDING = "\n";

    /**
     * Exactly one trailing newline — like every other text file in this tree.
     *
     * "Zero or one" is a diff nobody can read, and a POSIX text file ends in a newline.
     */
    public const string TRAILING_NEWLINE = "\n";

    /** Data, not a program. `replace()`'s own default would make it executable. */
    public const int FILE_MODE = 0644;

    /** Matches `Filesystem::ensureDirectoryExists()`'s own default, so the two never disagree. */
    public const int DIRECTORY_MODE = 0755;

    /**
     * Write one artifact's content to one path, atomically and at a mode nobody's umask decides.
     *
     * The directory is ensured first because `replace()` does not do it and does not complain —
     * measured. The mode is passed rather than defaulted for the same reason: the two things this
     * call must not inherit from the machine it runs on are where the file went and what it is
     * allowed to do.
     *
     * A regenerated artifact always ends at {@see self::FILE_MODE}, whatever it was before. That is
     * a deliberate reset of a file the tool owns, and it is the one place this path overrides
     * something a project may have set by hand — stated here rather than discovered later.
     */
    public static function write(Filesystem $files, string $path, string $content): void
    {
        $files->ensureDirectoryExists(dirname($path), self::DIRECTORY_MODE);

        $files->replace($path, $content, self::FILE_MODE);
    }

    /**
     * Whether a path, every symlink on the way to it resolved, still lies inside the root.
     *
     * The write follows a symlink: `replace()` resolves one at the target and replaces the file it
     * points to. A link committed into a repository can point anywhere, `../../` and absolute paths
     * included, so a target is checked before it is read, printed or written. A link that stays
     * inside the project, `CLAUDE.md` onto `AGENTS.md`, is an ordinary setup and passes.
     *
     * The deepest part of the path that exists is what gets resolved, because a file not written
     * yet can still sit under a linked directory. A link that leads nowhere cannot be shown to stay
     * inside, and is answered as not staying.
     */
    public static function staysInside(string $root, string $path): bool
    {
        $existing = $path;

        while (! file_exists($existing) && ! is_link($existing) && dirname($existing) !== $existing) {
            $existing = dirname($existing);
        }

        $resolved = realpath($existing);
        $base = realpath($root);

        return $resolved !== false && $base !== false
            && ($resolved === $base || str_starts_with($resolved, rtrim($base, DIRECTORY_SEPARATOR).DIRECTORY_SEPARATOR));
    }

    /**
     * Text as an artifact carries it: one line ending, exactly one trailing newline.
     *
     * Applied at the seam rather than trusted to each renderer, so "the file ends in a newline" is
     * a property of the format instead of a habit three authors happened to share.
     */
    public static function normalize(string $content): string
    {
        $normalized = str_replace(["\r\n", "\r"], self::LINE_ENDING, $content);

        return rtrim($normalized, "\n").self::TRAILING_NEWLINE;
    }
}
