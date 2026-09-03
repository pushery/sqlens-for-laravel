<?php

declare(strict_types=1);

namespace Pushery\SQLens\Generation;

use Pushery\SQLens\Contracts\MetadataRenderer;
use Pushery\SQLens\Reporting\Agent\Redactor;

/**
 * One generator, several outputs — the technical form of the promise that preventive guidance and
 * actual enforcement cannot drift.
 *
 * Every renderer is fed the SAME {@see RuleCatalogSnapshot} and nothing else. Not the rule
 * registry, not the configuration, not a connection: one question was asked once, and every
 * artifact answers from that one answer. A renderer allowed to consult the registry itself would
 * be a second source, and two sources agree for a long time before disagreeing quietly in the one
 * direction nobody checks.
 *
 * ## It renders; it never writes
 *
 * `export()` returns {@see GeneratedArtifact} values. This class has no filesystem, is handed no
 * filesystem, and could not write if it wanted to. The only code that writes is the command,
 * behind its `--check` branch — which is what makes `--check` and writing one path with one branch
 * at the end instead of two paths that agree until they do not.
 *
 * ## Families are load-bearing, not descriptive
 *
 * A renderer declares which family it belongs to, and `export()` runs exactly one family. Without
 * that, the day the documentation and SARIF renderers are registered, `sqlens:agent-rules` in a
 * consuming application would begin writing this package's documentation pages into somebody
 * else's repository. The grouping belongs in the scaffolding rather than in the renderers that
 * arrive later, because by then it would be a behavior change in a released command.
 */
final class MetadataExporter
{
    /** @var array<string, list<MetadataRenderer>> family value => its renderers, in registration order */
    private array $renderers = [];

    /**
     * @param  Redactor  $redactor  masks credential values in every artifact before anything sees it
     */
    public function __construct(private readonly Redactor $redactor) {}

    /**
     * Register a renderer under the family it declares.
     *
     * An extra renderer needs no change to this class or to any suite — which is the whole point of
     * the seam, and is measured rather than claimed: the spike proved the same shape works on the
     * reporter registry at the installed Laravel 13.
     *
     * @throws UnregisterableRenderer when the declared family is not one this build knows, or when
     *                                two renderers of one family would write the same path
     */
    public function register(MetadataRenderer $renderer): void
    {
        $family = ArtifactFamily::named($renderer->family());

        if (! $family instanceof ArtifactFamily) {
            throw UnregisterableRenderer::unknownFamily($renderer->name(), $renderer->family(), ArtifactFamily::names());
        }

        $this->renderers[$family->value][] = $renderer;
    }

    /**
     * Every renderer of one family, in registration order.
     *
     * @return list<MetadataRenderer>
     */
    public function renderersFor(ArtifactFamily $family): array
    {
        return $this->renderers[$family->value] ?? [];
    }

    /**
     * The artifacts of ONE family, from one snapshot.
     *
     * Ordered by path rather than by registration, so the same set of renderers produces the same
     * report whatever order a service provider happened to register them in — the same determinism
     * the snapshot itself promises, one layer out.
     *
     * A second renderer of the same family writing the same path is refused here rather than at
     * registration, because it is a property of the PAIR: neither renderer is wrong on its own, and
     * whichever ran last would silently win.
     *
     * @return list<GeneratedArtifact>
     *
     * @throws UnregisterableRenderer
     */
    public function export(RuleCatalogSnapshot $snapshot, ArtifactFamily $family): array
    {
        $artifacts = [];
        $claimedBy = [];

        foreach ($this->renderersFor($family) as $renderer) {
            $artifact = $renderer->render($snapshot);

            $owner = $claimedBy[$artifact->path] ?? null;

            if ($owner !== null) {
                throw UnregisterableRenderer::duplicatePath($family->value, $artifact->path, $owner, $renderer->name());
            }

            $claimedBy[$artifact->path] = $renderer->name();

            // THE enforcement point for this family, and it is here rather than in each renderer for
            // the reason the reporter's is at its own single seam: a redactor each renderer had to
            // call is a redactor the next renderer can be written without. These artifacts are
            // COMMITTED into a consuming repository, so a leak here reaches the git history, every
            // review and every clone — the most durable form this exposure takes.
            //
            // After the renderer returns, so a renderer that appends to its own content on the way
            // out is masked too.
            $artifacts[] = $artifact->redactedWith($this->redactor);
        }

        usort($artifacts, static fn (GeneratedArtifact $a, GeneratedArtifact $b): int => strcmp($a->path, $b->path));

        return $artifacts;
    }
}
