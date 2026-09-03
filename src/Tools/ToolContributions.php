<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * The contributions a run may ask for, keyed by the tool they belong to.
 *
 * Deliberately separate from {@see KnownTools}: a tool can be KNOWN — worth reporting as missing,
 * worth counting in `sqlens:doctor` — long before anything can act on its output. The Squawk
 * adapter landed in exactly that order, and so did this one. Merging the two lists would force the
 * two decisions to be made together, which is how a run comes to report a loss it could not
 * collect on even with the binary installed.
 */
final readonly class ToolContributions
{
    /** @var array<string, ToolContribution> */
    private array $byTool;

    /** @param  list<ToolContribution>  $contributions */
    public function __construct(array $contributions = [])
    {
        $byTool = [];

        foreach ($contributions as $contribution) {
            $byTool[$contribution->toolName()] = $contribution;
        }

        $this->byTool = $byTool;
    }

    /** The contribution for a tool, or null when nothing can act on that tool's output yet. */
    public function for(Tool $tool): ?ToolContribution
    {
        return $this->byTool[$tool->name()] ?? null;
    }
}
