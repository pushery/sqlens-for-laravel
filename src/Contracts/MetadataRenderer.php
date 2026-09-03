<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Generation\GeneratedArtifact;
use Pushery\SQLens\Generation\RuleCatalogSnapshot;

/**
 * One artifact, rendered from the active rule catalog.
 *
 * A renderer takes the snapshot and returns TEXT. It never reads the rule registry — that would be
 * a second source of truth, and two sources drift in exactly the direction nobody checks — and it
 * never touches a filesystem. The only code that writes is the command, behind its `--check`
 * branch, so `--check` and writing are one code path with one branch at the very end rather than
 * two paths that agree until they do not.
 *
 * That is structural, not a convention: a renderer CANNOT write, because it is never handed
 * anything to write with.
 */
interface MetadataRenderer
{
    /**
     * Which family this renderer's output belongs to — a value of {@see ArtifactFamily}.
     *
     * Declared rather than inferred, because the consequence of getting it wrong lands in somebody
     * else's repository: a renderer registered without a placeable family would run under
     * `--target=all` in a consuming application and write a file nobody there ordered.
     */
    public function family(): string;

    /** A stable name for this renderer, used in errors and in `--check` output. */
    public function name(): string;

    /** The artifact, from the snapshot and from nothing else. */
    public function render(RuleCatalogSnapshot $snapshot): GeneratedArtifact;
}
