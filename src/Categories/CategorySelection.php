<?php

declare(strict_types=1);

namespace Pushery\SQLens\Categories;

use Pushery\SQLens\Exceptions\UnknownCategory;

/**
 * Parses the `--category` option into a validated set of categories. The option is
 * repeatable AND comma-separable — `--category=safety --category=idiom` and
 * `--category=safety,idiom` mean the same thing — so each raw token is split on
 * commas, trimmed, and matched against the Category enum.
 *
 * An unknown category is a misconfiguration, never a silently dropped token: a run
 * that quietly filtered to nothing would look exactly like "clean", which is the
 * false green this package exists to refuse. The order is normalized to the enum's
 * own declaration order and duplicates are collapsed, so the header renders the
 * same selection regardless of how the user typed it.
 */
final readonly class CategorySelection
{
    /** @param  list<Category>  $categories */
    private function __construct(public array $categories) {}

    /**
     * @param  list<string>  $rawTokens  the repeated `--category` values, each possibly comma-joined
     *
     * @throws UnknownCategory when a token names no known category
     */
    public static function parse(array $rawTokens): self
    {
        $seen = [];

        foreach ($rawTokens as $rawToken) {
            foreach (explode(',', $rawToken) as $piece) {
                $name = trim($piece);

                if ($name === '') {
                    continue;
                }

                $category = Category::tryFrom($name)
                    ?? throw UnknownCategory::named($name);

                $seen[$category->value] = $category;
            }
        }

        return self::ordered($seen);
    }

    /**
     * The scope a RUN is narrowed to: the `--category` values when the flag was given, else the
     * project's `sqlens.categories`.
     *
     * ## Why both suites come through here
     *
     * `--category` means the same thing in `sqlens:lint` and `sqlens:audit`, and a user who has
     * learned one has learned both — which is only true while there is ONE implementation of what
     * "defaults to the configured set" means. It was two: the lint runner read the key, the audit
     * runner did not, and the difference was invisible from either side. A project that scoped its
     * audit in `config/sqlens.php` got every category checked, with a header that said `categories=all`
     * and nothing on screen to say the scope had been dropped — a run that answered a question
     * nobody asked, and the shape of silence this package exists to refuse.
     *
     * ## null is not an empty list
     *
     * `null` means the flag was ABSENT, and only then does the configured list apply. An empty list
     * is a project saying "every category". Collapsing the two would make a configured scope
     * unreachable from any command invoked without the flag — which is every scheduled run there is.
     *
     * ## Lenient here, loud elsewhere
     *
     * Unlike {@see parse()} this drops a value it does not recognize instead of throwing. Both
     * inputs have already met somebody louder: the flag went through `parse()` in the command, and
     * the config key is an enum-list leaf the config validator refuses before anything connects. A
     * second rejection at this depth would surface the same typo twenty seconds into a catalog read.
     *
     * @param  list<string>|null  $flagValues  the validated `--category` values, or null when the flag was absent
     * @param  mixed  $configured  the raw `sqlens.categories` value, in whatever shape the config holds it
     */
    public static function forRun(?array $flagValues, mixed $configured): self
    {
        $values = $flagValues ?? (is_array($configured) ? array_values(array_filter($configured, is_string(...))) : []);

        $seen = [];

        foreach ($values as $value) {
            $category = Category::tryFrom($value);

            if ($category instanceof Category) {
                $seen[$category->value] = $category;
            }
        }

        return self::ordered($seen);
    }

    /**
     * Normalize to the enum's declaration order so the same selection, however typed or configured,
     * renders identically in the header — and so two runs of an unchanged project cannot produce two
     * different `categories=` lines.
     *
     * @param  array<string, Category>  $seen  keyed by value, so duplicates already collapsed
     */
    private static function ordered(array $seen): self
    {
        return new self(array_values(array_filter(
            Category::cases(),
            static fn (Category $category): bool => isset($seen[$category->value]),
        )));
    }

    /**
     * The selected category values, in a stable order — what the reporter shows and
     * what the runner stores in the header. Empty means "no filter": all categories.
     *
     * @return list<string>
     */
    public function values(): array
    {
        return array_map(static fn (Category $category): string => $category->value, $this->categories);
    }
}
