<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

use Pushery\SQLens\Reporting\RunProfile;

/**
 * Resolves WHICH profile a run uses, in one fixed, deterministic order:
 *
 *     --profile flag  →  SQLENS_PROFILE env  →  config  →  built-in default
 *
 * The order is the whole point: the same repository state produces the same active
 * profile on a dev Mac and in CI, so a result can be reproduced. Nothing is guessed
 * — in particular APP_ENV is never read. Deriving the profile from the framework's
 * environment is exactly the implicit skew this refuses: a machine whose APP_ENV
 * happened to be "production" would silently run a different gate than the same
 * command on a laptop. If you want CI to run the ci profile, CI says so, explicitly.
 *
 * The config source is the EXISTING `sqlens.profile` key — not a second
 * `default_profile`. That key already is the config-level default profile, is
 * validated by the schema, and appears in the run header; giving profiles their own
 * parallel key would be two config surfaces for one concept, the drift every guard
 * here prevents.
 *
 * A source "provides" a value when it is present at all. A present-but-empty or
 * present-but-unknown value is REJECTED, not skipped: `--profile=` or an unknown
 * name is a mistake the user should hear about, not a reason to fall through to a
 * default they did not ask for.
 */
final readonly class ProfileSelector
{
    /** The profile a run uses when no source names one — the lenient, report-only default. */
    public const string BUILT_IN_DEFAULT = 'local';

    /**
     * @param  list<string>  $known  the profile names the config declares (RunProfile's cases)
     */
    public function __construct(private array $known) {}

    /** Build against the profiles the shipped enum knows. */
    public static function forKnownProfiles(): self
    {
        return new self(array_map(static fn (RunProfile $profile): string => $profile->value, RunProfile::cases()));
    }

    /**
     * Resolve the active profile. Each argument is the value that source supplied,
     * or null when the source did not set it at all (the flag was absent, the env
     * var was unset, the config key was missing). An empty string is NOT null — it
     * is a value the user provided, and an empty value is rejected.
     */
    public function select(?string $flag, ?string $env, ?string $config, ?string $commandDefault = null): ProfileSelection
    {
        [$value, $source] = match (true) {
            $flag !== null => [$flag, 'flag'],
            $env !== null => [$env, 'env'],
            $config !== null => [$config, 'config'],
            // A command that exists for ONE place answers for that place when nobody said
            // otherwise: `sqlens:predeploy` runs on a deploy host, and falling back to the profile
            // of a developer laptop there is how a gate ends up lenient on the one server where it
            // matters. It sits BELOW all three user-set sources, so a flag, the environment and a
            // configured profile still win in that order.
            $commandDefault !== null => [$commandDefault, 'command default'],
            default => [self::BUILT_IN_DEFAULT, 'default'],
        };

        if (! in_array($value, $this->known, true)) {
            return ProfileSelection::rejected($value, $source);
        }

        return ProfileSelection::resolved($value, $source);
    }

    /** The profile names this selector accepts — for a rejection message. */
    public function knownProfiles(): string
    {
        return implode(', ', $this->known);
    }
}
