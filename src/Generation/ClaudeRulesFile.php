<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use Pushery\SQLens\Generation\Renderers\Frontmatter;

/**
 * A Claude target written into the agent's rules directory, where it is a rule of its own rather than a section.
 *
 * The Claude format has no header, because its default home is a section inside the project's own `CLAUDE.md`. Sent to
 * `.claude/rules/` with `--output`, the same block becomes a file the agent reads as a rule, and a rule without a
 * `paths:` header applies to every file and is loaded into every session. So the file gets the scope the other two
 * formats carry as their glob: the migrations and the configuration this guidance is about.
 */
final class ClaudeRulesFile
{
    /** The files the rule is about, beside the migrations. */
    private const array CONFIGURATION = ['config/database.php', 'config/sqlens.php'];

    /** Whether a repo-relative path names a markdown file in the agent's rules directory. */
    public static function covers(string $relative): bool
    {
        $path = str_replace('\\', '/', str_starts_with($relative, './') ? substr($relative, 2) : $relative);

        return str_starts_with($path, '.claude/rules/') && str_ends_with($path, '.md');
    }

    /**
     * The file's content with the `paths:` header on top, unless the file already opens with a header of its own.
     *
     * A header the project wrote stays exactly as it is, and so does every line outside the markers: the header is
     * only ever added, to a new file or to one that has none.
     */
    public static function withHeader(?string $existing, string $content): string
    {
        if ($existing !== null && preg_match('/\A---\r?\n/', $existing) === 1) {
            return $content;
        }

        return Frontmatter::render(['paths' => [AgentContextFormat::MIGRATION_GLOB, ...self::CONFIGURATION]]).$content;
    }
}
