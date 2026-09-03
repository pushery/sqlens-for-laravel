<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\Support;

/**
 * The flags in a `sql_mode` value, asked by name.
 *
 * ## Why this is a class and not a `str_contains`
 *
 * `str_contains($mode, 'NO_ZERO_DATE')` is true for a server carrying only `NO_ZERO_IN_DATE` — a
 * different flag whose name happens to contain the other. Four rules judge flags inside this one
 * variable, and four independent substring checks is four chances for that.
 *
 * Splitting on the comma is the whole implementation, and that is the point: it is not clever, it is
 * simply done ONCE.
 *
 * ## Combination modes are not expanded here
 *
 * MySQL expands `TRADITIONAL` and friends on assignment, so a server that was set with a combination
 * word reports the individual flags back. What arrives from `performance_schema` or `SHOW` is
 * therefore already the expanded list, and expanding again here would be inventing an answer the
 * server did not give — the shape of guess this package refuses. A value that somehow still carried
 * a combination word would fail the `has()` check and produce a finding, which is the cautious
 * direction: it says "I do not see this flag", not "this flag is absent".
 */
final readonly class SqlModeFlags
{
    /** @param  list<string>  $flags */
    private function __construct(private array $flags) {}

    /** The flags a server reported, split and folded. */
    public static function parse(string $value): self
    {
        $flags = [];

        foreach (explode(',', $value) as $flag) {
            $trimmed = strtoupper(trim($flag));

            if ($trimmed !== '') {
                $flags[] = $trimmed;
            }
        }

        return new self($flags);
    }

    /** Whether this exact flag is present — never a substring match. */
    public function has(string $flag): bool
    {
        return in_array(strtoupper(trim($flag)), $this->flags, true);
    }

    /** Whether the server reported no flags at all, which is itself an answer. */
    public function isEmpty(): bool
    {
        return $this->flags === [];
    }
}
