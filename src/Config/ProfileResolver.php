<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

use Illuminate\Contracts\Config\Repository;

/**
 * Resolves what a setting is actually worth for this run, in one fixed order:
 *
 *     base config  →  active profile  →  command-line flag
 *
 * The flag always wins. That is the whole contract, and it is the reason profiles
 * are safe to adopt: turning on the `ci` profile can never take away a one-off
 * `--level=6`, so nobody has to reason about which of two strictness settings is
 * in force. The order is reported in the run header, so a result can be traced
 * back to the settings that produced it.
 *
 * A profile is a PARTIAL override — a setting it does not name keeps its base
 * value. The resolver therefore distinguishes "the profile sets this to null"
 * from "the profile does not set this at all"; collapsing the two would make
 * `assume_server_version => null` in a profile silently mean "no opinion" when
 * the user wrote "no pin".
 *
 * Which settings are overridable is the schema's answer, not this class's — see
 * {@see ConfigSchema::PROFILE_OVERRIDABLE}. The validator has already rejected an
 * unknown profile name and an unknown key inside one before a run reaches here,
 * so this class resolves rather than re-judges.
 */
final readonly class ProfileResolver
{
    public function __construct(private Repository $config) {}

    /**
     * The effective value of an overridable path.
     *
     * `$cliValue` is what the command line supplied, or null when the flag was
     * absent — the CLI has no way to say "explicitly null", so null is unambiguous
     * here, which is exactly why the profile layer needs the richer
     * has-it/does-not-have-it test below and this layer does not.
     */
    public function value(string $path, mixed $cliValue = null): mixed
    {
        if ($cliValue !== null) {
            return $cliValue;
        }

        $overrides = $this->overrides();

        return array_key_exists($path, $overrides)
            ? $overrides[$path]
            : $this->config->get('sqlens.'.$path);
    }

    /**
     * Every overridable setting with its effective value, keyed by path — what the
     * run header reports and what a caller applies in one pass.
     *
     * @param  array<string, mixed>  $cliValues  keyed by path; a null (or absent) entry means the flag was not given
     * @return array<string, mixed>
     */
    public function values(array $cliValues = []): array
    {
        $resolved = [];

        foreach (ConfigSchema::PROFILE_OVERRIDABLE as $path) {
            $resolved[$path] = $this->value($path, $cliValues[$path] ?? null);
        }

        return $resolved;
    }

    /** The active profile's name — the `profile` key, which the validator has already checked. */
    public function activeProfile(): string
    {
        $profile = $this->config->get('sqlens.profile');

        return is_string($profile) ? $profile : '';
    }

    /**
     * The active profile's overrides, flattened to the same dotted paths the
     * schema declares. Only paths the profile actually SETS appear, so a caller
     * can tell an override apart from a base value.
     *
     * @return array<string, mixed>
     */
    private function overrides(): array
    {
        $profile = $this->config->get('sqlens.profiles.'.$this->activeProfile());

        if (! is_array($profile)) {
            return [];
        }

        $overrides = [];

        foreach (ConfigSchema::PROFILE_OVERRIDABLE as $path) {
            $value = $this->dig($profile, explode('.', $path));

            if ($value !== self::class) {
                $overrides[$path] = $value;
            }
        }

        return $overrides;
    }

    /**
     * Read a nested path out of a profile array, returning this class's own name
     * as the "absent" marker. A sentinel rather than null, because null is a legal
     * VALUE for one of the overridable settings — `assume_server_version` uses it to mean
     * "no pin", and reading that as "unset" would silently restore the base value the
     * profile meant to clear. (`security.min_severity` used to be the second such key; its
     * off-switch is now the word `none` and null is refused outright, so it no longer
     * depends on this distinction.)
     *
     * @param  array<array-key, mixed>  $profile
     * @param  list<string>  $segments
     */
    private function dig(array $profile, array $segments): mixed
    {
        $cursor = $profile;

        foreach ($segments as $segment) {
            if (! is_array($cursor) || ! array_key_exists($segment, $cursor)) {
                return self::class;
            }

            $cursor = $cursor[$segment];
        }

        return $cursor;
    }
}
