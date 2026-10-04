<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Pushery\SQLens\Categories\CategoryFilter;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Levels\LevelGate;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * What one amplifier adds to a run that has already made up its own mind.
 *
 * ## Why this is a contract and not an `instanceof`
 *
 * The lint route folds its tool in by asking `instanceof SquawkTool`, and that shape is exactly
 * what carried the defect in the suppression bookkeeping beside it: a runner that names one tool
 * has to be edited for the second, and the edit that gets forgotten is invisible — no test fails,
 * the tool is simply never asked.
 *
 * So the audit route resolves through this instead. A tool with no contribution registered is
 * simply not asked; a tool with one is asked by name it does not have to spell.
 *
 * ## The merge is one-directional, and that is part of the contract
 *
 * An implementation ADDS findings. It must not remove, re-rank or re-decide one the run already
 * made: a machine with the binary installed must not gate differently from one without it, beyond
 * having more checks. And it must not throw — an amplifier that ends the run that asked it is
 * worse than one that is absent.
 */
interface ToolContribution
{
    /** The {@see Tool::name()} this contributes for. */
    public function toolName(): string;

    /**
     * @param  list<Finding>  $own  what the run's own rules produced
     * @param  ToolFindingGate  $gate  the run's level and category gates, which the tool's verdicts pass like a rule's
     * @return list<Finding>
     */
    public function contribute(array $own, ToolDiagnostic $diagnostic, string $connectionName, SubjectContext $context, ?string $pinnedHost = null, ToolFindingGate $gate = new ToolFindingGate(new LevelGate(Level::Pedantic), new CategoryFilter([]))): array;

    /**
     * The ids this tool reports a verdict under that a run behind this gate does not ask for.
     *
     * A baseline entry under one of them cannot be matched in such a run, so the run must not call
     * it stale.
     *
     * @return list<string>
     */
    public function unaskedIds(ToolFindingGate $gate): array;
}
