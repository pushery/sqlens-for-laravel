<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Config\ProfileResolver;
use Pushery\SQLens\Config\ProfileSelection;
use Pushery\SQLens\Config\ProfileSelector;
use Pushery\SQLens\ShippedLocale;

/**
 * Shared `--profile` resolution for every suite command. A command applies the
 * precedence — flag → SQLENS_PROFILE → config → built-in default — and, on a valid
 * result, writes the chosen name back onto the single `sqlens.profile` config key
 * so everything downstream (the run header, the profile overrides) sees exactly the
 * profile the user selected. There is no second selection path: the commands differ
 * in what they DO with a run, not in how they pick a profile.
 *
 * The env var is read HERE, at the command boundary, so the resolver itself stays a
 * pure value operation over three explicit strings — testable without touching the
 * process environment.
 */
trait ResolvesProfile
{
    /**
     * Resolve and apply the active profile. Returns the selection so the caller can
     * turn an invalid one into a misconfiguration; a valid one has already been
     * written to config by the time this returns.
     */
    private function resolveProfile(Repository $config): ProfileSelection
    {
        $flag = $this->option('profile');
        $env = getenv('SQLENS_PROFILE');
        $configured = $config->get('sqlens.profile');

        $selection = ProfileSelector::forKnownProfiles()->select(
            is_string($flag) ? $flag : null,
            $env === false ? null : $env,
            is_string($configured) ? $configured : null,
        );

        if ($selection->isValid()) {
            // One source of truth: the resolved profile becomes the value every
            // reader already consults, rather than a parameter threaded in parallel.
            $config->set('sqlens.profile', $selection->profile);
            $this->applyProfileOverrides($config);
        }

        return $selection;
    }

    /**
     * Bake the active profile's overrides onto the base config, so the run reads its
     * effective (base → profile) value for each overridable setting without any reader
     * having to learn about profiles. The command-line flags stay ABOVE this: the
     * runner layers `--level` / `--strict-tools` / `--assume-server-version` over the
     * config it reads here, so the full precedence base → profile → flag holds with no
     * value threaded twice — the overrides written here carry no flag layer (the
     * resolver is asked with no CLI values).
     *
     * This is the single seam that turns the profile config from values on a shelf
     * into a run that actually gates differently. It runs at the command boundary, so
     * a direct LintRunner call (a test, an internal caller) is unaffected unless it
     * opts in — the command is where a user's profile choice enters.
     */
    private function applyProfileOverrides(Repository $config): void
    {
        foreach (new ProfileResolver($config)->values() as $path => $value) {
            $config->set('sqlens.'.$path, $value);
        }
    }

    /** The translated misconfiguration line for a rejected profile — naming it and the legal set. */
    private function profileRejectionMessage(ProfileSelection $selection): string
    {
        return $this->translate('sqlens::messages.commands.unknown_profile', [
            'profile' => (string) $selection->rejectedValue,
            'available' => ProfileSelector::forKnownProfiles()->knownProfiles(),
        ]);
    }

    /**
     * Translate a message key through the Translator CONTRACT, resolved from the
     * command's container, rather than the global `trans()` helper. `trans()` is
     * defined only in the framework's Foundation, which this package deliberately does
     * NOT require (illuminate/* only) — so a lean host would fatal on it. The contract
     * lives in illuminate/contracts, which the package does require. Shared here so
     * every suite command routes translation the one lean-safe way.
     *
     * ⚠️ THE LOCALE IS PASSED EXPLICITLY, AND THIS CALL DID NOT. It is the sixth resolution
     * point in the package; the five that existed when the rule was written all pass the
     * constant, and this trait was added afterwards without it. Nothing about the omission
     * looks wrong, and nothing goes red: on the usual host the fallback chain reaches `en`
     * anyway. On a host that sets BOTH `app.locale` and `app.fallback_locale` to its own
     * language — a German shop on `de`/`de`, which is an ordinary setup rather than a corner
     * — there is no path to English at all, and the translator returns the key it was given.
     *
     * Every profile, severity and format diagnostic in `sqlens:lint`, `sqlens:audit`,
     * `sqlens:security` and `sqlens:baseline` routes through here, so on such a host the user
     * would read `sqlens::messages.commands.unknown_profile` where a sentence belongs — while
     * being told their configuration is wrong.
     *
     * @param  array<string, string|int>  $replace
     */
    private function translate(string $key, array $replace = []): string
    {
        return (string) $this->laravel->make(Translator::class)->get($key, $replace, ShippedLocale::CODE);
    }
}
