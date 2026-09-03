<?php

declare(strict_types=1);

namespace Pushery\SQLens\Categories;

use Pushery\SQLens\Contracts\Rule;

/**
 * The category axis, the second filter beside the level gate. It narrows a run to
 * one or more categories (safety, performance, idiom, convention, security,
 * privacy) without touching the level semantics — the two axes are orthogonal.
 *
 * It runs AFTER the level gate, over the rules that level already admitted, so the
 * order of the two axes is deterministic: level decides strictness, category then
 * decides subject. An empty selection means "every category" — the filter passes
 * the input straight through rather than inventing a meaning for "none".
 *
 * Unlike the level gate, the category axis has no severity exception: a run asked
 * for `--category=idiom` genuinely wants only idiom, so a security rule is not
 * forced back in. The "a level-0 run still reports a critical" guarantee lives on
 * the LEVEL axis (LevelGate), not here.
 */
final readonly class CategoryFilter
{
    /** @param  list<Category>  $selected  the categories to keep; empty means all */
    public function __construct(private array $selected) {}

    /** Whether this filter narrows anything — an empty selection is "all", not a filter. */
    public function isActive(): bool
    {
        return $this->selected !== [];
    }

    /**
     * The rules that survive the category filter: all of them when the selection is
     * empty (no narrowing), otherwise those whose category is in the selection.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function apply(array $rules): array
    {
        if (! $this->isActive()) {
            return $rules;
        }

        return array_values(array_filter(
            $rules,
            fn (Rule $rule): bool => in_array($rule->category(), $this->selected, true),
        ));
    }
}
