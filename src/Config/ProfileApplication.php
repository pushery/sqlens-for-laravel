<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

use Closure;
use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Reporting\RunProfile;

/**
 * Chooses the profile a run uses and applies it, for every caller that starts one: the suite
 * commands and the MCP tools that call the same services.
 *
 * The choice follows one order, the name the caller was given → `SQLENS_PROFILE` → `sqlens.profile`
 * → the caller's own default → `local`. Applying it writes the name onto `sqlens.profile` and the
 * profile's overrides onto the keys every reader consults, so the engines see the profile without
 * any of them learning about profiles.
 *
 * One class for both callers, because a second reading of the same settings is a second answer
 * about one migration. The tools used to call the services with the base configuration: a project
 * whose `ci` profile raises the level got the stricter verdict from `sqlens:lint --profile=ci` and
 * the base one from `lint_pending` with `profile: ci`, under a run header naming the profile it had
 * not applied.
 *
 * The environment variable is read here, at the boundary both callers pass through, so the selector
 * stays a pure value operation over the strings it is handed.
 */
final readonly class ProfileApplication
{
    public function __construct(private Repository $config) {}

    /**
     * The profile names a caller may ask for, the same set `--profile` accepts.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_map(static fn (RunProfile $profile): string => $profile->value, RunProfile::cases());
    }

    /**
     * Choose the profile for a run.
     *
     * `$requested` is the name the caller was given, the command's `--profile` or a tool's `profile`
     * parameter, and null when it was given none. `$default` is the answer of a caller that exists
     * for one place, `sqlens:predeploy` on a deploy host; it sits below every source a user sets.
     */
    public function select(?string $requested, ?string $default = null): ProfileSelection
    {
        $env = getenv('SQLENS_PROFILE');
        $configured = $this->config->get('sqlens.profile');

        return ProfileSelector::forKnownProfiles()->select(
            $requested,
            $env === false ? null : $env,
            is_string($configured) ? $configured : null,
            $default,
        );
    }

    /**
     * Write a valid selection onto the configuration: its name onto `sqlens.profile`, and each
     * overridable setting's effective value (base, then profile) onto its key.
     *
     * The caller's own flags and parameters stay above this. The services layer `level` and
     * `strict_tools` over the configuration they read, so the order base → profile → flag holds
     * without a value being passed twice.
     */
    public function apply(ProfileSelection $selection): void
    {
        $this->config->set('sqlens.profile', $selection->profile);

        foreach (new ProfileResolver($this->config)->values() as $path => $value) {
            $this->config->set('sqlens.'.$path, $value);
        }
    }

    /**
     * Run `$run` under a valid selection, and put back every key the selection wrote once it
     * returns or throws.
     *
     * For a caller that answers many runs in one process. The MCP server answers every tool call
     * in the same process, so a profile left in place by one call would be the configuration the
     * next call starts from.
     *
     * @template T
     *
     * @param  Closure(): T  $run
     * @return T
     */
    public function during(ProfileSelection $selection, Closure $run): mixed
    {
        $before = ProfileKeys::of($this->config);

        try {
            $this->apply($selection);

            return $run();
        } finally {
            $before->restore();
        }
    }
}
