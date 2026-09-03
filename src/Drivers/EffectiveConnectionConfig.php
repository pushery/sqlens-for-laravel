<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Illuminate\Database\ConfigurationUrlParser;
use Illuminate\Support\Arr;

/**
 * The connection config the FRAMEWORK would use — never the raw array.
 *
 * Laravel does not read `database.connections.<name>` verbatim. It runs the entry through
 * {@see ConfigurationUrlParser}, so a `url`-only connection HAS a driver, a host and a database
 * name — extracted from the URL — none of which appear as keys in the config file. And for a
 * read/write split it merges the `write` block over the base.
 *
 * ## Why this is its own class rather than a private method
 *
 * Because three callers need the same answer and only one of them had it. {@see DriverManager} did
 * this correctly and said so in its docblock; `InstanceResolver` and `sqlens:doctor` read
 * `$settings['driver']` straight out of the array. On a url-only connection — the shape this parser
 * exists to handle — that reads null, so `doctor` printed `driver=unknown` and the audit refused a
 * configuration Laravel and `sqlens:lint` both accept.
 *
 * Two of the three agreeing was never going to hold. One implementation answering one question is
 * what makes "the config the framework would use" a fact rather than a claim each caller re-derives.
 *
 * ## Why the WRITE side
 *
 * A migration runs against the primary, and every judgment SQLens makes is about the instance a
 * migration will actually run against. `ConnectionFactory` merges the `write` block over the base
 * for exactly that reason, so the same merge happens here.
 */
final readonly class EffectiveConnectionConfig
{
    /**
     * The parsed, write-merged config for one connection entry.
     *
     * Takes the shape a config repository actually hands back — keys of any type, values of any
     * type — rather than a narrowed one no caller can guarantee. A non-array is an empty result
     * rather than a throw: "this connection is not configured" is a state every caller already
     * has an answer for, and a crash here would replace that answer with a stack trace.
     *
     * @return array<string, mixed>
     */
    public static function for(mixed $config): array
    {
        if (! is_array($config)) {
            return [];
        }

        $keyed = [];

        foreach ($config as $key => $value) {
            $keyed[(string) $key] = $value;
        }

        /** @var array<string, mixed> $parsed */
        $parsed = new ConfigurationUrlParser()->parseConfiguration($keyed);

        $write = $parsed['write'] ?? null;

        if (is_array($write)) {
            /** @var array<string, mixed> $parsed */
            $parsed = Arr::except(array_merge($parsed, $write), ['read', 'write']);
        }

        return $parsed;
    }

    /** The driver this connection resolves to, or null when it names none. */
    public static function driverFor(mixed $config): ?string
    {
        $driver = self::for($config)['driver'] ?? null;

        return is_string($driver) && $driver !== '' ? $driver : null;
    }
}
