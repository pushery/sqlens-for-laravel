<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard;

use Pushery\SQLens\Exceptions\InvalidGuardProfile;

/**
 * One named set of runtime guardrails, resolved once and never re-read.
 *
 * ## Why a type and not the config array
 *
 * A guardrail that read `config('sqlens.guard.profiles.production.strict.throw')` would carry a
 * verdict its own tests cannot see: the value arrives from a global, so an arm proving the guardrail
 * works proves nothing about what a real application would hand it. Every guardrail here takes this
 * object, and this object is built in exactly one place.
 *
 * It also makes the honest failure possible. A missing key is a DEFAULT — a project that published
 * `config/sqlens.php` before a key existed must keep working — while an unknown key is an ERROR,
 * because a typo that silently disabled a guardrail is the whole thing this suite exists to
 * prevent. An array cannot tell those apart; a constructor with named defaults and a validator can.
 *
 * ## Immutable, and with no request state
 *
 * `phpstan.neon.dist` runs `checkOctaneCompatibility: true`, so a guard object holding request state
 * on a container singleton is a gate failure rather than a production incident. Nothing here changes
 * after construction, and the cumulative slow-query accounting that DOES need per-request state
 * lives in the guardrail that owns it rather than in the profile it reads.
 */
final readonly class GuardProfile
{
    /**
     * @param  list<string>  $connections  the connections this profile applies to; empty means all
     */
    private function __construct(
        public string $name,
        public bool $lazyLoading,
        public bool $discardingAttributes,
        public bool $missingAttributes,
        public bool $destructiveCommands,
        public bool $throw,
        public bool $slowQueryEnabled,
        public int $slowQueryThresholdMs,
        public int $cumulativeThresholdMs,
        public bool $runtimeDdl,
        public bool $unboundRawSql,
        public ?string $logChannel,
        public string $logLevel,
        public bool $includeBindings,
        public int $maxSqlLength,
        public array $connections,
    ) {}

    /**
     * The profile a configuration names, or a refusal that says which name it could not find.
     *
     * ⚠️ An unknown name is an EXCEPTION and never "off". The two are indistinguishable in their
     * effect and opposite in their meaning: off is a decision somebody made, and an unknown name is
     * a typo that turned every guardrail in the application into a no-op while the config still
     * reads as though they are on.
     *
     * @param  array<string, mixed>  $guard  the `sqlens.guard` block
     * @param  list<string>  $knownConnections  what `database.connections` defines
     * @param  list<string>  $knownChannels  what `logging.channels` defines
     *
     * @throws InvalidGuardProfile
     */
    public static function resolve(array $guard, array $knownConnections = [], array $knownChannels = []): ?self
    {
        $name = $guard['profile'] ?? null;

        if ($name === null) {
            return null;
        }

        if (! is_string($name) || $name === '') {
            throw InvalidGuardProfile::notAName($name);
        }

        $profiles = is_array($guard['profiles'] ?? null) ? $guard['profiles'] : [];

        if (! array_key_exists($name, $profiles) || ! is_array($profiles[$name])) {
            throw InvalidGuardProfile::unknownProfile($name, array_map(strval(...), array_keys($profiles)));
        }

        /** @var array<string, mixed> $definition */
        $definition = $profiles[$name];

        return self::fromDefinition($name, $definition, $knownConnections, $knownChannels);
    }

    /**
     * @param  array<string, mixed>  $definition
     * @param  list<string>  $knownConnections
     * @param  list<string>  $knownChannels
     *
     * @throws InvalidGuardProfile
     */
    private static function fromDefinition(string $name, array $definition, array $knownConnections, array $knownChannels): self
    {
        $strict = self::section($definition, 'strict');
        $slow = self::section($definition, 'slow_query');
        $runtime = self::section($definition, 'runtime');
        $logging = self::section($definition, 'logging');

        $channel = $logging['channel'] ?? null;

        // Checked at BOOT rather than at the first violation, and the difference is the whole
        // value: a channel that does not exist throws inside the logger, which is reached only when
        // a guardrail finally has something to say. That is the worst possible moment to discover a
        // configuration error — the application is already misbehaving, and now the thing that was
        // supposed to report it is the thing that fails.
        if (is_string($channel) && $knownChannels !== [] && ! in_array($channel, $knownChannels, true)) {
            throw InvalidGuardProfile::unknownChannel($name, $channel, $knownChannels);
        }

        $connections = [];

        foreach (is_array($definition['connections'] ?? null) ? $definition['connections'] : [] as $named) {
            // Stringly rather than cast: a non-string here is a configuration error the validator
            // already refuses, and casting one would invent a name to compare against.
            if (! is_string($named) || $named === '') {
                throw InvalidGuardProfile::unknownConnection($name, get_debug_type($named), $knownConnections);
            }

            $connection = $named;

            // Same reasoning one field over: a connection name nothing defines means the guardrail
            // is silently off for the connection somebody meant to protect, and a whitelist that
            // matches nothing looks exactly like a whitelist that matches everything.
            if ($knownConnections !== [] && ! in_array($connection, $knownConnections, true)) {
                throw InvalidGuardProfile::unknownConnection($name, $connection, $knownConnections);
            }

            $connections[] = $connection;
        }

        return new self(
            name: $name,
            lazyLoading: self::flag($strict, 'lazy_loading'),
            discardingAttributes: self::flag($strict, 'discarding_attributes'),
            missingAttributes: self::flag($strict, 'missing_attributes'),
            destructiveCommands: self::flag($strict, 'destructive_commands'),
            // FALSE unless a profile says otherwise, and the default is primum non nocere rather
            // than timidity: a guardrail that takes an application down in production is worse than
            // the thing it guards against, and the log line says everything the exception would.
            throw: self::flag($strict, 'throw'),
            slowQueryEnabled: self::flag($slow, 'enabled'),
            slowQueryThresholdMs: self::positiveInt($name, $slow, 'threshold_ms', 1000),
            cumulativeThresholdMs: self::positiveInt($name, $slow, 'cumulative_threshold_ms', 5000),
            runtimeDdl: self::flag($runtime, 'runtime_ddl'),
            unboundRawSql: self::flag($runtime, 'unbound_raw_sql'),
            logChannel: is_string($channel) && $channel !== '' ? $channel : null,
            logLevel: is_string($logging['level'] ?? null) ? $logging['level'] : 'warning',
            // FALSE unless asked for. Bindings are row data, and a log is the one place row data
            // reaches somewhere with different access rules than the database it came from.
            includeBindings: self::flag($logging, 'include_bindings'),
            maxSqlLength: self::positiveInt($name, $logging, 'max_sql_length', 2000),
            connections: $connections,
        );
    }

    /** Whether this profile watches a given connection. An empty whitelist means every one. */
    public function watches(string $connection): bool
    {
        return $this->connections === [] || in_array($connection, $this->connections, true);
    }

    /** Whether anything here needs a query listener at all. */
    public function needsQueryListener(): bool
    {
        return $this->slowQueryEnabled || $this->runtimeDdl || $this->unboundRawSql;
    }

    /**
     * @param  array<string, mixed>  $definition
     * @return array<string, mixed>
     */
    private static function section(array $definition, string $key): array
    {
        if (! is_array($definition[$key] ?? null)) {
            return [];
        }

        /** @var array<string, mixed> $section */
        $section = $definition[$key];

        return $section;
    }

    /**
     * A boolean that DEFAULTS TO FALSE and refuses anything that is not one.
     *
     * No coercion, deliberately. `'false'` is truthy in PHP, so a project writing it in an
     * environment-driven config would turn a guardrail on while believing it had turned it off —
     * and the config validator refuses it for the same reason. This is the second line of that
     * defense, for a profile built from an array the validator never saw.
     *
     * @param  array<string, mixed>  $section
     */
    private static function flag(array $section, string $key): bool
    {
        return ($section[$key] ?? false) === true;
    }

    /**
     * @param  array<string, mixed>  $section
     *
     * @throws InvalidGuardProfile
     */
    private static function positiveInt(string $profile, array $section, string $key, int $default): int
    {
        if (! array_key_exists($key, $section)) {
            return $default;
        }

        $value = $section[$key];

        // Zero is refused rather than read as "no bound". A threshold of zero reports every query
        // ever run and a truncation length of zero logs the empty string — both are an unset value
        // spelled wrongly, and both make the guardrail useless in a way that looks like it works.
        if (! is_int($value) || $value <= 0) {
            throw InvalidGuardProfile::notPositive($profile, $key, $value);
        }

        return $value;
    }
}
