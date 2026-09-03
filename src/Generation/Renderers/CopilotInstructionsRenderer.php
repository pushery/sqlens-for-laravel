<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation\Renderers;

use Pushery\SQLens\Contracts\MetadataRenderer;
use Pushery\SQLens\Generation\AgentContextFormat;
use Pushery\SQLens\Generation\ArtifactFamily;
use Pushery\SQLens\Generation\GeneratedArtifact;
use Pushery\SQLens\Generation\RuleCatalogSnapshot;

/**
 * The path-scoped instructions file — also a file this tool owns whole.
 *
 * ## Why this target and not the repository-wide one
 *
 * The vendor documents two shapes. `.github/copilot-instructions.md` belongs to the PROJECT, is
 * documented as capped at about two pages and as "not task specific" — which a generated rule
 * catalog is exactly, and writing one there would spend a budget the team needs on content that
 * has its own file available. The path-scoped file is scoped by `applyTo`, has no stated cap, and
 * is ours.
 *
 * That also settles a question the ticket left the other way round: because this file is ours, it
 * needs no marker mechanic. Only the Claude target writes into somebody else's document.
 *
 * ## Compact, and what compact is not
 *
 * One line per rule instead of a block. It is NOT a shorter list: a rule missing from an agent's
 * context is a rule that agent will break, and it will do so silently, because nothing in the file
 * says what is absent.
 */
final readonly class CopilotInstructionsRenderer implements MetadataRenderer
{
    public function __construct(
        private string $generatorVersion,
        private string $migrationGlob = 'database/migrations/**/*.php',
    ) {}

    public function family(): string
    {
        return ArtifactFamily::AgentRules->value;
    }

    public function name(): string
    {
        return 'copilot';
    }

    public function render(RuleCatalogSnapshot $snapshot): GeneratedArtifact
    {
        $format = AgentContextFormat::Copilot;

        $content = Frontmatter::render($format->frontmatter($this->migrationGlob))
            ."\n"
            .GeneratedNotice::forWholeFile($this->generatorVersion, $snapshot->hash())
            ."\n\n"
            .RuleGuidance::body($snapshot, compact: true);

        return GeneratedArtifact::wholeFile($format->path(), $content, ArtifactFamily::AgentRules, $snapshot->hash());
    }
}
