<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Arr;

/**
 * The config keys a suite command writes for its profile, as they stood before it wrote them.
 *
 * A command applies its profile by writing onto the config every reader consults: the profile's
 * name onto `sqlens.profile`, the profile's overrides onto their keys, and `--min-severity` onto the
 * severity floor. Those writes are meant for that one run. Left in place, they were inherited by the
 * next command in the same process, a `$this->call()` from an application command, an
 * `Artisan::call()` in a queue job or an Octane worker: `sqlens:predeploy` after an `sqlens:audit`
 * found `local` configured, which outranks its own default, and gated on `critical` instead of
 * `high`. So a command reads these keys before its first write and puts them back when it returns.
 */
final readonly class ProfileKeys
{
    /**
     * @param  array<string, mixed>  $values  the value of each key the config held, by its path below `sqlens`
     * @param  list<string>  $absent  the paths of the keys it did not hold
     */
    private function __construct(
        private Repository $config,
        private array $values,
        private array $absent,
    ) {}

    public static function of(Repository $config): self
    {
        $values = [];
        $absent = [];

        foreach (['profile', ...ConfigSchema::PROFILE_OVERRIDABLE] as $path) {
            if ($config->has('sqlens.'.$path)) {
                $values[$path] = $config->get('sqlens.'.$path);
            } else {
                $absent[] = $path;
            }
        }

        return new self($config, $values, $absent);
    }

    /** Put back every key as it stood, and take out again each one the config did not hold. */
    public function restore(): void
    {
        foreach ($this->values as $path => $value) {
            $this->config->set('sqlens.'.$path, $value);
        }

        if ($this->absent === []) {
            return;
        }

        // Taken out rather than set to null. A key the application left out is one the validator
        // reads as defaulted, and a null in place of `level` or `security.min_severity` is one it
        // refuses: a run that put back null would have the next command refuse a configuration
        // nobody changed.
        $section = (array) $this->config->get('sqlens', []);

        Arr::forget($section, $this->absent);

        $this->config->set('sqlens', $section);
    }
}
