<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation\Renderers;

use Pushery\SQLens\Contracts\MetadataRenderer;
use Pushery\SQLens\Generation\AgentContextFormat;
use Pushery\SQLens\Generation\ArtifactFamily;
use Pushery\SQLens\Generation\GeneratedArtifact;
use Pushery\SQLens\Generation\MarkerBlock;
use Pushery\SQLens\Generation\RuleCatalogSnapshot;

/**
 * A section inside a file the PROJECT owns — the only one of the three that is.
 *
 * It must replace itself on the second run rather than duplicate, and leave the handwritten rest
 * untouched. That is not a nicety: a command that produced a merge conflict or ate somebody's
 * paragraph once is a command nobody runs a second time, and the whole feature is worth nothing
 * unrun.
 *
 * The mechanic itself lives in {@see MarkerBlockWriter}, which owns every state a real file can be
 * in. This renderer only produces the body and declares the marker pair — the seven states, the
 * idempotence and the byte-exact preservation of the neighbor's text are proven there, once, for
 * both callers.
 *
 * ## Compact, and the measurement that decided it
 *
 * The vendor documents a target of under 200 lines for this whole file, and it is the PROJECT's
 * file — the team's own instructions share that budget. Rendered in the full per-rule form, this
 * block measured 287 lines over a level-2 catalog of 54 rules, so the generated section alone would
 * have blown the budget it exists to respect, and would grow with every level the project raises.
 * The compact form is 75 lines over the same catalog and lists exactly the same rules.
 *
 * That is a real constraint rather than a preference, and it is the strongest argument for the
 * alternative target recorded in the format spike: a path-scoped rules file carries no such budget
 * and loads only when somebody touches a migration. Raised with the owner rather than switched to
 * unilaterally.
 *
 * ## No generated-file notice here, and that is deliberate
 *
 * The other two targets carry one, because a reader opening a file this tool owns has no other
 * signal. Here the marker pair IS the signal, and it is visible to a person reading the raw
 * markdown while costing the model nothing — the vendor documents that block-level HTML comments
 * are stripped before the file reaches it. A second notice inside the block would be text the model
 * DOES read, spending part of that file's stated context budget to say something the reader can
 * already see.
 */
final readonly class ClaudeMarkdownRenderer implements MetadataRenderer
{
    public function __construct(private string $generatorVersion) {}

    public function family(): string
    {
        return ArtifactFamily::AgentRules->value;
    }

    public function name(): string
    {
        return 'claude';
    }

    public function render(RuleCatalogSnapshot $snapshot): GeneratedArtifact
    {
        $format = AgentContextFormat::Claude;

        // The pair is asked of MarkerBlock rather than of the format's nullable accessor: this
        // renderer KNOWS it writes a region, and defending against a null that cannot happen would
        // be a branch no test can reach. The format table still answers the general question.
        $markers = MarkerBlock::agentRules($this->generatorVersion, $snapshot->hash());

        return GeneratedArtifact::markedRegion(
            $format->path(),
            '## Database migration rules'."\n\n".RuleGuidance::body($snapshot, compact: true),
            ArtifactFamily::AgentRules,
            $snapshot->hash(),
            $markers->openLine,
            $markers->closeLine,
        );
    }
}
