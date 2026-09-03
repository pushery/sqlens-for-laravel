<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

/**
 * Where each coding-agent format wants its file, and what that file has to look like.
 *
 * These are three FOREIGN conventions belonging to three other vendors, and they move. Every value
 * below was read from the vendor's own documentation on 2026-08-07 rather than recalled — a guessed
 * path or a guessed frontmatter field produces a file the target tool never reads, and nothing
 * turns red to say so. That is the failure this enum exists to make impossible: one place holds
 * them, and a test pins every one, so a vendor moving something breaks a build instead of quietly
 * emptying an artifact of its effect.
 *
 * ## The three are not the same shape, and that decides more than it looks like
 *
 * Two of them get a file the TOOL owns — one rule per file, written whole. Only the Claude format
 * writes a SECTION into a file the PROJECT owns, which is the one case that needs the marker
 * mechanic at all. A renderer set built on the assumption that all three need it would carry the
 * mechanism into two places that have no use for it.
 *
 * ## Why the Claude markers are HTML comments
 *
 * Not for looks. The vendor documents that block-level HTML comments are stripped from the file
 * before it reaches the model, so the marker pair costs the reader nothing and does not compete
 * with that file's stated 200-line budget. It follows that nothing meaningful may live ON the
 * marker line — the version and hash it carries are for a human and for `--check`, and the model
 * never sees them.
 */
enum AgentContextFormat: string
{
    /** A section inside the project's own Claude instructions file. */
    case Claude = 'claude';

    /** A rule file this tool owns, under the editor's rules directory. */
    case Cursor = 'cursor';

    /** A path-scoped instructions file this tool owns. */
    case Copilot = 'copilot';

    /**
     * The repo-relative path this format's artifact is written to.
     *
     * Copilot offers a repository-wide file as well; the path-scoped one is chosen because the
     * repository-wide file is the project's, is documented as capped at about two pages, and is
     * documented as "not task specific" — which a generated rule catalog is exactly.
     */
    public function path(): string
    {
        return match ($this) {
            self::Claude => 'CLAUDE.md',
            // `.mdc`, not `.md`: a plain markdown file in that directory is ignored by the rules
            // system, so the extension is the difference between a rule and an inert file.
            self::Cursor => '.cursor/rules/sqlens-migrations.mdc',
            // The name must end in `.instructions.md` or the file is not picked up.
            self::Copilot => '.github/instructions/sqlens-migrations.instructions.md',
        };
    }

    /**
     * Whether this format writes a marked section into a file somebody else also writes in.
     *
     * True for exactly one of the three, and the asymmetry is the point: the other two own their
     * whole file, so a marker there would be ceremony around a region with no neighbors.
     */
    public function writesMarkedRegion(): bool
    {
        return $this === self::Claude;
    }

    /**
     * The marker pair for a format that writes a region, or null for one that owns its file.
     *
     * The syntax comes from here rather than from the writer, because it is a property of the
     * TARGET FILE's language: an HTML comment is invisible in rendered markdown, and the Claude
     * file is markdown a person reads.
     */
    public function markers(string $generatorVersion, string $snapshotHash): ?MarkerBlock
    {
        if (! $this->writesMarkedRegion()) {
            return null;
        }

        return MarkerBlock::agentRules($generatorVersion, $snapshotHash);
    }

    /**
     * The frontmatter this format's file carries, in a fixed key order.
     *
     * Empty for the Claude format, which has none — a section inside somebody else's markdown
     * cannot introduce a document header.
     *
     * The glob is deliberately the same subject in all three: this package's guidance is about
     * migrations, and loading it into every session of every editor would spend a budget each
     * vendor documents as scarce.
     *
     * @param  string  $migrationGlob  the project's migration path pattern
     * @return array<string, string|bool>
     */
    public function frontmatter(string $migrationGlob): array
    {
        return match ($this) {
            self::Claude => [],
            // Exactly the three fields the vendor documents. `alwaysApply: false` plus `globs` is
            // the documented combination for "apply to specific files".
            self::Cursor => [
                'description' => 'Database migration safety rules generated from the project SQLens configuration',
                'globs' => $migrationGlob,
                'alwaysApply' => false,
            ],
            // `applyTo` is the one required field. `excludeAgent` is deliberately not set: both
            // surfaces that read this file — code review and the cloud agent — want the guidance,
            // and omitting the field is how the vendor documents "both".
            self::Copilot => ['applyTo' => $migrationGlob],
        };
    }
}
