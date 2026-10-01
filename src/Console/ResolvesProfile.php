<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Config\ProfileApplication;
use Pushery\SQLens\Config\ProfileKeys;
use Pushery\SQLens\Config\ProfileSelection;
use Pushery\SQLens\Config\ProfileSelector;
use Pushery\SQLens\ShippedLocale;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Shared `--profile` resolution for every suite command. A command applies the
 * precedence — flag → SQLENS_PROFILE → config → built-in default — and, on a valid
 * result, writes the chosen name back onto the single `sqlens.profile` config key
 * so everything downstream (the run header, the profile overrides) sees exactly the
 * profile the user selected. There is no second selection path: the commands differ
 * in what they DO with a run, not in how they pick a profile, and the MCP tools choose
 * through the same {@see ProfileApplication}.
 *
 * Those writes last as long as the run. The keys are read before the first one and put back
 * when the command returns, however it returns, so the next command in the same process starts
 * from the configuration the application set rather than from this command's profile.
 */
trait ResolvesProfile
{
    /** The profile keys as they stood before this run wrote any of them, while the run lasts. */
    private ?ProfileKeys $keysBeforeProfile = null;

    /**
     * Run the command, and put the profile keys back once it returns or throws.
     *
     * Here rather than in `handle()`, because every way into a command passes through it:
     * `php artisan`, `Artisan::call()`, and `$this->call()` from an application command.
     */
    public function run(InputInterface $input, OutputInterface $output): int
    {
        try {
            return parent::run($input, $output);
        } finally {
            $this->keysBeforeProfile?->restore();
            $this->keysBeforeProfile = null;
        }
    }

    /**
     * Resolve and apply the active profile. Returns the selection so the caller can
     * turn an invalid one into a misconfiguration; a valid one has already been
     * written to config by the time this returns.
     */
    private function resolveProfile(Repository $config, ?string $commandDefault = null): ProfileSelection
    {
        $flag = $this->option('profile');
        $profiles = new ProfileApplication($config);

        // The default sits below the three user-set sources, and only a command that exists for
        // one place passes one -- see the selector.
        $selection = $profiles->select(is_string($flag) ? $flag : null, $commandDefault);

        if ($selection->isValid()) {
            // Read before the first write, so what `run()` puts back is what the application
            // set. `--min-severity` is written after this, onto a key read here too.
            $this->keysBeforeProfile ??= ProfileKeys::of($config);

            // One source of truth: the resolved profile becomes the value every reader already
            // consults, rather than a parameter threaded in parallel. A direct service call (a
            // test, an internal caller) is unaffected unless it applies one too.
            $profiles->apply($selection);
        }

        return $selection;
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
     * The locale is passed explicitly, as at every other resolution point in the package. Nothing
     * about an omission would look wrong, and nothing would go red: on the usual host the fallback
     * chain reaches `en` anyway. On a host that sets both `app.locale` and `app.fallback_locale` to
     * its own language — a German shop on `de`/`de`, which is an ordinary setup rather than a corner
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
