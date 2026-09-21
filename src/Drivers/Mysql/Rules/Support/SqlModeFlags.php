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
 * server did not give — the shape of guess this package refuses.
 *
 * ⚠️ THE COMBINATION WORD COMES BACK TOO, ALONGSIDE ITS EXPANSION — this paragraph used to treat that
 * as a remote case ("a value that somehow still carried a combination word"), and it is the NORMAL
 * state of any server set that way. Measured on 8.4.10, over all three read paths:
 *
 *     SET SESSION sql_mode = 'TRADITIONAL'
 *       -> STRICT_TRANS_TABLES,STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,
 *          ERROR_FOR_DIVISION_BY_ZERO,TRADITIONAL,NO_ENGINE_SUBSTITUTION
 *
 * It costs nothing, because `has('STRICT_TRANS_TABLES')` finds the expansion. What the old wording
 * got backwards is the conclusion: it said such a value "would fail the `has()` check and produce a
 * finding". It does not, and that is correct — but anyone building a guard on the old sentence would
 * pin an untruth, namely that this value never carries a combination word.
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
