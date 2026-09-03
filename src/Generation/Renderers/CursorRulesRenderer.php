<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation\Renderers;

use Pushery\SQLens\Contracts\MetadataRenderer;
use Pushery\SQLens\Generation\AgentContextFormat;
use Pushery\SQLens\Generation\ArtifactFamily;
use Pushery\SQLens\Generation\GeneratedArtifact;
use Pushery\SQLens\Generation\RuleCatalogSnapshot;

/**
 * The editor rules file — a file this tool owns whole.
 *
 * Owning the file is what makes this the simple one of the three: there is no neighbor's text to
 * preserve, so no marker mechanic, and the whole document is rewritten each run. The path and the
 * three frontmatter fields come from {@see AgentContextFormat}, which read them from the vendor's
 * own documentation — a renderer that invented either would produce a file the editor never reads,
 * and nothing would turn red to say so.
 *
 * The generated-file notice is not politeness. This file looks hand-written, sits in version
 * control, and will be edited by somebody who has no reason to suspect it is regenerated; the
 * notice is what stops their edit from being silently thrown away on the next run.
 */
final readonly class CursorRulesRenderer implements MetadataRenderer
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
        return 'cursor';
    }

    public function render(RuleCatalogSnapshot $snapshot): GeneratedArtifact
    {
        $format = AgentContextFormat::Cursor;

        $content = Frontmatter::render($format->frontmatter($this->migrationGlob))
            ."\n"
            .GeneratedNotice::forWholeFile($this->generatorVersion, $snapshot->hash())
            ."\n\n"
            .RuleGuidance::body($snapshot);

        return GeneratedArtifact::wholeFile($format->path(), $content, ArtifactFamily::AgentRules, $snapshot->hash());
    }
}
