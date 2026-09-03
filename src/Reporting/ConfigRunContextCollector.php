<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use BackedEnum;
use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Contracts\RunContextCollector;
use Pushery\SQLens\PackageVersion;
use Pushery\SQLens\Rules\StabilityGate;
use Pushery\SQLens\Severity\Severity;

/**
 * The trivial collector for now: it reads the run's mode, profile, and strict flags
 * from config (falling back to safe defaults) and the package version from Composer's
 * installed-versions manifest. It probes NO server and discovers NO tools yet — the
 * server- and tool-version collection lands with the capture and audit suites, so
 * those two lists are empty here. Reading no live state also keeps it deterministic
 * and side-effect-free, which is exactly what a reproducibility header needs.
 */
final readonly class ConfigRunContextCollector implements RunContextCollector
{
    public function __construct(private Repository $config) {}

    /**
     * @param  array<string, int|null>|null  $sessionTimeouts  what a preflight session reported IN
     *                                                         FORCE, null for a producer that
     *                                                         opens none
     * @param  int|null  $timeBudgetMsConsumed  what the whole run cost, for a producer with a time
     *                                          budget; null for the lint and audit runs, which have
     *                                          none
     */
    public function collect(?array $sessionTimeouts = null, ?string $checkTimings = null, ?int $timeBudgetMsConsumed = null): RunContext
    {
        return new RunContext(
            serverVersions: [],
            toolVersions: [],
            mode: $this->enum('sqlens.mode', CaptureMode::class, CaptureMode::Static),
            profile: $this->enum('sqlens.profile', RunProfile::class, RunProfile::Local),
            strictTools: $this->config->get('sqlens.strict_tools') === true,
            strictUndetermined: $this->config->get('sqlens.strict_undetermined') === true,
            // Never config-driven: the roundtrip is a CLI flag for one run, so the
            // base context this collector describes is always "not asked for". The
            // run overrides it with the flag it actually received.
            roundtrip: false,
            sqlensVersion: PackageVersion::current(),
            level: $this->level(),
            minSeverity: $this->minSeverity(),
            // Read here, so every producer carries it without each one remembering to: the
            // question is which tiers this CONFIGURATION admits, and configuration is what this
            // collector is for.
            admittedStability: StabilityGate::fromConfig($this->config->get('sqlens.stability'))->admittedNames(),
            sessionTimeouts: $sessionTimeouts,
            checkTimings: $checkTimings,
            timeBudgetMsConsumed: $timeBudgetMsConsumed,
            // Read here rather than derived from whether anything was armed, and the difference is
            // the whole point: `off` has to be SAID. A deactivated guard that does not appear in a
            // header reads exactly like an active one, and a reader scanning for it and finding
            // nothing concludes the field is not emitted by this version.
            guardProfile: self::guardProfileFrom($this->config),
        );
    }

    /**
     * The active runtime-guard profile name, or the literal `off`.
     *
     * A STATIC, and it is the reason there is one: four different places build a `RunContext` — this
     * collector, the lint runner, the audit runner and the security command — and a field that each
     * of them read for itself would be four chances for one to forget. A forgotten one emits null,
     * which in this field means "this producer has no guard stage at all", so the mistake would
     * publish a lie rather than an obvious gap.
     */
    public static function guardProfileFrom(Repository $config): string
    {
        return is_string($guard = $config->get('sqlens.guard.profile')) && $guard !== '' ? $guard : 'off';
    }

    /** The configured strictness level 0–9, clamped; a non-int or absent key is level 0. */
    private function level(): int
    {
        $configured = $this->config->get('sqlens.level');

        return is_int($configured) ? max(0, min(9, $configured)) : 0;
    }

    /**
     * The configured security-severity floor, or null when the gate is off (`none`).
     *
     * A value this does not recognize also resolves to null, and that is deliberate rather than
     * lenient: the CONFIG VALIDATOR is what refuses a typo, before any run starts, with the
     * misconfiguration exit code and a message naming the legal values. By the time a collector
     * reads the key the value has already been judged, so a second opinion here would only decide
     * what happens in a state that cannot be reached — and a validator whose guarantee is quietly
     * duplicated downstream is a validator somebody eventually stops running.
     */
    private function minSeverity(): ?Severity
    {
        $configured = $this->config->get('sqlens.security.min_severity');

        return is_string($configured) ? Severity::tryFrom($configured) : null;
    }

    /**
     * Read a string-backed enum from config, falling back to $default when the key
     * is absent or holds an unknown value — an unknown mode/profile is never a fatal,
     * it is the documented default.
     *
     * @template T of \BackedEnum
     *
     * @param  class-string<T>  $enum
     * @param  T  $default
     * @return T
     */
    private function enum(string $key, string $enum, BackedEnum $default): BackedEnum
    {
        $value = $this->config->get($key);

        return is_string($value) ? ($enum::tryFrom($value) ?? $default) : $default;
    }
}
