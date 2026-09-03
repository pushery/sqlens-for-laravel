<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * The name shapes an expand/contract migration leaves behind, and the discipline that keeps them
 * from becoming noise.
 *
 * ## Why this is a NAME match, and why that is admitted rather than hidden
 *
 * An abandoned rename chain leaves `users_old`. A backfill helper leaves `tmp_backfill_state`. A
 * dated snapshot leaves `orders_20260721`. None of those is distinguishable, in the catalog, from a
 * table somebody meant to keep — `orders_old` is a perfectly reasonable name for an archive a team
 * queries every quarter.
 *
 * So the match is a heuristic and the check that uses it never returns `fail` on a pattern alone.
 * A heuristic that presents itself as certainty burns the feature: the first false positive on a
 * table people rely on is the last time anybody reads the report.
 *
 * ## The defaults are deliberately conservative
 *
 * Every suffix here is one a person writes when they mean "temporary" and almost never otherwise,
 * and each is anchored at the END of the bare name. `_old` matches `users_old` and not
 * `threshold_settings`; `tmp_` is anchored at the start for the same reason.
 *
 * What is deliberately NOT here: `_v2`, `_copy_of`, `_a`/`_b`, and anything shorter than three
 * characters. Each of those appears in real, permanent schemas often enough that including it would
 * spend the check's credibility to catch a case the dated suffix already covers.
 */
final readonly class TransitionObjectPatterns
{
    /**
     * The shipped list, as PCRE patterns against the BARE object name.
     *
     * Patterns rather than plain suffixes because one of them is not a suffix at all — a dated
     * snapshot is `_20260721`, eight digits, and a literal list could not express it. The rest read
     * as suffixes because that is what they are.
     *
     * @var list<string>
     */
    public const array SHIPPED = [
        '/_old$/',
        '/_new$/',
        '/_tmp$/',
        '/_temp$/',
        '/_bak$/',
        '/_backup$/',
        '/_copy$/',
        '/_migration$/',
        // A dated suffix: `orders_20260721`. Eight digits, because six would also match a version
        // number and four would match a year somebody put in a real table name on purpose.
        '/_\d{8}$/',
        '/^tmp_/',
    ];

    /** @param  list<string>  $patterns */
    private function __construct(public array $patterns) {}

    public static function shipped(): self
    {
        return new self(self::SHIPPED);
    }

    /**
     * The patterns a project configured, falling back to the shipped list for anything unusable.
     *
     * A pattern PCRE cannot compile is DROPPED rather than allowed to throw, and the fallback is the
     * shipped list rather than an empty one: an empty list would silence the check completely, and a
     * project reading "no findings" as "nothing left behind" is the failure this package refuses.
     *
     * @param  mixed  $configured  the raw `deploy.postdeploy.transition_patterns` value
     */
    public static function fromConfig(mixed $configured): self
    {
        if (! is_array($configured)) {
            return self::shipped();
        }

        $usable = array_values(array_filter(
            $configured,
            static fn (mixed $pattern): bool => is_string($pattern)
                && $pattern !== ''
                && @preg_match($pattern, '') !== false,
        ));

        return $usable === [] ? self::shipped() : new self($usable);
    }

    /** Whether this bare object name looks like a transition leftover. */
    public function matches(string $bareName): bool
    {
        return array_any($this->patterns, fn (string $pattern): bool => preg_match($pattern, $bareName) === 1);
    }
}
