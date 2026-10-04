<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Categories\CategoryFilter;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Levels\LevelGate;

/**
 * The run's gates, applied to what an external tool found.
 *
 * A tool's verdict passes the two gates a rule passes: the level, under which security and privacy
 * are gated by severity instead, and the category selection. Both decisions are the rule gates'
 * own, asked with the finding's level and category, so a tool cannot be gated by a second reading
 * of either. Without them an installed binary widens a run the user narrowed on purpose: the level
 * band and the category selection are an appetite the project chose, and a tool has no standing to
 * overrule it.
 *
 * Only verdicts are gated. An undetermined says the tool could not answer, and that is governed by
 * the undetermined policy and strict mode, not by an appetite for strictness. Hiding it under a
 * narrow setting would turn "nobody checked" into "nothing found", which is the silent green this
 * package exists to refuse.
 */
final readonly class ToolFindingGate
{
    public function __construct(private LevelGate $level, private CategoryFilter $categories) {}

    /** Every level and every category: the gate of a run that narrowed nothing. */
    public static function open(): self
    {
        return new self(new LevelGate(Level::Pedantic), new CategoryFilter([]));
    }

    /** Whether a run behind this gate asks for a verdict at this level and in this category. */
    public function asks(Level $level, Category $category): bool
    {
        return $this->level->admitsAt($level, $category) && $this->categories->admits($category);
    }

    public function admits(Finding $finding): bool
    {
        return $finding->status->outcome === Outcome::Undetermined || $this->asks($finding->level, $finding->category);
    }

    /**
     * @param  list<Finding>  $findings
     * @return list<Finding>
     */
    public function apply(array $findings): array
    {
        return array_values(array_filter($findings, $this->admits(...)));
    }
}
