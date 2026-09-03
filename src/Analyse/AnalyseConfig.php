<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Pushery\SQLens\Exceptions\InvalidAnalyseConfiguration;

/**
 * The analyse suite's configuration, validated at construction.
 *
 * ## Why validation lives here and not in the neon schema
 *
 * PHPStan's `parametersSchema` already refuses an unknown KEY and a wrong TYPE, and that half is
 * left to it — re-implementing it here would give two answers to one question. What it cannot do is
 * refuse a wrong VALUE: `policy: documentd` is a perfectly good string. So the value checks sit in
 * this constructor, and they throw rather than fall back.
 *
 * Falling back is the tempting half and the wrong one. A project that mistypes the mode would get a
 * green run under a duty it did not choose — and if the typo silences the rule, the project believes
 * it has a guarantee it does not. That is the silent green this package refuses, applied to its own
 * configuration surface.
 *
 * ## The default is a real object, not null
 *
 * Every consumer of this class takes it with `= new AnalyseConfig` as the default, so a run without
 * a `parameters.sqlens` block behaves exactly like one that spelled the defaults out. Without that,
 * "not configured" and "configured to the default" would be two code paths, and only one of them
 * would be exercised by the fixtures.
 */
final readonly class AnalyseConfig
{
    public AnalysePolicy $policy;

    /**
     * Absolute, existing paths the duty does not apply to.
     *
     * @var list<string>
     */
    public array $excludePaths;

    /**
     * Reasons that do not count as reasons under {@see AnalysePolicy::Strict}, lower-cased.
     *
     * @var list<string>
     */
    public array $justificationPlaceholders;

    /**
     * @param  list<string>  $excludePaths
     * @param  list<string>  $justificationPlaceholders
     */
    public function __construct(
        string|bool $policy = 'documented',
        array $excludePaths = [],
        array $justificationPlaceholders = [],
    ) {
        $this->policy = AnalysePolicy::fromConfig($policy);
        $this->excludePaths = $this->resolved($excludePaths);
        $this->justificationPlaceholders = $this->placeholders($justificationPlaceholders);
    }

    /** Does this run ask for a written reason at all? */
    public function asksForAReason(): bool
    {
        return $this->policy->asksForAReason();
    }

    /**
     * Is this file inside the scope the duty applies to?
     *
     * Compared on the resolved path plus a separator, so `src/Generated` never excludes
     * `src/GeneratedThings.php` — a prefix match without the separator silently widens an
     * exemption, which is the direction that turns rules off.
     */
    public function covers(string $file): bool
    {
        $resolved = realpath($file);

        // An unresolvable path is COVERED rather than excluded. The two failure directions are not
        // symmetric: treating it as excluded would drop a call site out of the report for a reason
        // nobody can see, while treating it as covered at worst reports one that a project then
        // excludes on purpose.
        if ($resolved === false) {
            return true;
        }

        return array_all($this->excludePaths, fn (string $excluded): bool => $resolved !== $excluded && ! str_starts_with($resolved, $excluded.DIRECTORY_SEPARATOR));
    }

    /**
     * Does this reason satisfy the duty?
     *
     * Whitespace never counts, in any mode — that check lives in the collector and is older than
     * this class. What the mode decides is whether a reason that says something UNHELPFUL counts:
     * `todo` is a sentence, and under `documented` it is accepted, because a team mid-adoption is
     * better served by an annotation it can grep for than by a rule it switched off.
     */
    public function accepts(string $reason): bool
    {
        $trimmed = trim($reason);

        if ($trimmed === '') {
            return false;
        }

        if (! $this->policy->weighsTheReason()) {
            return true;
        }

        return ! in_array(mb_strtolower($trimmed), $this->justificationPlaceholders, true);
    }

    /**
     * The exclude paths as absolute paths, or a named refusal.
     *
     * @param  list<string>  $paths
     * @return list<string>
     */
    private function resolved(array $paths): array
    {
        $resolved = [];

        foreach ($paths as $path) {
            $absolute = realpath($path);

            if ($absolute === false) {
                throw InvalidAnalyseConfiguration::missingExcludePath($path);
            }

            $resolved[] = $absolute;
        }

        sort($resolved);

        return $resolved;
    }

    /**
     * The placeholder list, lower-cased and de-duplicated.
     *
     * @param  list<string>  $placeholders
     * @return list<string>
     */
    private function placeholders(array $placeholders): array
    {
        $normalized = [];

        foreach ($placeholders as $placeholder) {
            $trimmed = trim($placeholder);

            if ($trimmed === '') {
                throw InvalidAnalyseConfiguration::blankPlaceholder();
            }

            $normalized[] = mb_strtolower($trimmed);
        }

        $unique = array_values(array_unique($normalized));
        sort($unique);

        return $unique;
    }
}
