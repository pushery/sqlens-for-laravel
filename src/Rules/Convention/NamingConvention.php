<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Convention;

/**
 * What a project says an identifier should look like, and which identifiers it does not judge.
 *
 * ## Built once, handed down — never read by a rule
 *
 * The same rule the money-column dictionary follows, and for the same reason: a rule that read the
 * configuration would have a verdict its own tests cannot see, and two rules reading one key would
 * eventually disagree about what a malformed value means. There are two naming rules, one per
 * engine, sharing one judgment — so there is exactly one place this may be built.
 *
 * ## The pattern is validated BEFORE this exists
 *
 * `ConfigSchema` refuses a pattern PCRE cannot compile, and that refusal is load-bearing rather
 * than tidy. `preg_match()` answers `false` for a broken pattern, not `0`, and `false !== 1` — so a
 * single typo in a project's pattern would report every identifier in the database as a violation,
 * with nothing in the output pointing at the setting.
 *
 * This class is the second line for the same reason every other value object here has one: a
 * registry built directly in a test, or by a consuming application, never passed through the
 * validator. An unusable pattern falls back to the shipped default rather than to "everything
 * fails" — the failure direction that reports LESS is the safe one for a convention rule, because
 * the alternative floods a report and gets the rule switched off.
 */
final readonly class NamingConvention
{
    /**
     * @param  string  $pattern  a PCRE the identifier must match
     * @param  list<string>  $exempt  PCREs naming identifiers this rule does not judge at all
     * @param  string  $foreignKeySuffix  what a single-column foreign key's name is expected to end with
     */
    private function __construct(
        public string $pattern,
        public array $exempt,
        public string $foreignKeySuffix = ForeignKeyIdSuffix::DEFAULT_SUFFIX,
    ) {}

    /** The shipped convention: snake_case, no leading digit, foreign keys ending in `_id`. */
    public static function shipped(): self
    {
        return new self(SnakeCaseIdentifiers::DEFAULT_PATTERN, [], ForeignKeyIdSuffix::DEFAULT_SUFFIX);
    }

    /**
     * The convention a project configured, falling back to the shipped one for anything unusable.
     *
     * @param  mixed  $naming  the raw `sqlens.audit.naming` value
     */
    public static function fromConfig(mixed $naming): self
    {
        if (! is_array($naming)) {
            return self::shipped();
        }

        $pattern = $naming['pattern'] ?? null;

        $suffix = $naming['foreign_key_suffix'] ?? null;

        return new self(
            is_string($pattern) && @preg_match($pattern, '') !== false ? $pattern : SnakeCaseIdentifiers::DEFAULT_PATTERN,
            self::usablePatterns($naming['exempt'] ?? null),
            // An EMPTY suffix is refused rather than honored, and the direction matters: every
            // name ends with the empty string, so an empty setting would silence the rule
            // completely — a project would read "no findings" and believe its keys are named the
            // way it asked, when in fact it asked for nothing and got nothing checked.
            is_string($suffix) && $suffix !== '' ? $suffix : ForeignKeyIdSuffix::DEFAULT_SUFFIX,
        );
    }

    /**
     * Whether this identifier is one the project asked not to be judged.
     *
     * Matched against the BARE name rather than the qualified one, because that is what the rule
     * judges — an exemption written against `app.legacy_Table` would silently never fire, and a
     * pattern that matches nothing is an exemption a project believes it has.
     */
    public function exempts(string $identifier): bool
    {
        return array_any($this->exempt, static fn (string $pattern): bool => @preg_match($pattern, $identifier) === 1);
    }

    /**
     * The entries that are usable patterns, and nothing else.
     *
     * A non-string or an uncompilable pattern is DROPPED rather than kept: an exemption that cannot
     * match is an exemption that does nothing, and keeping it would make `exempts()` answer false
     * for a reason no reader could see. The config validator has already refused both shapes by the
     * time this runs; this is the second line for a registry built outside it.
     *
     * @return list<string>
     */
    private static function usablePatterns(mixed $exempt): array
    {
        if (! is_array($exempt)) {
            return [];
        }

        return array_values(array_filter(
            $exempt,
            static fn (mixed $entry): bool => is_string($entry) && @preg_match($entry, '') !== false,
        ));
    }
}
