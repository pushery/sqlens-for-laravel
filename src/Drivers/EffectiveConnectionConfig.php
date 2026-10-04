<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\ConfigurationUrlParser;
use Illuminate\Database\Connection;
use Illuminate\Support\Arr;
use ReflectionClass;

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
        $parsed = self::withoutUrl($config);

        $write = $parsed['write'] ?? null;

        // `ConnectionFactory::make()` opens a split only when a `read` block is set. Without one it
        // connects with the connection's own keys and never reads a `write` block, so neither does
        // this: a `database` in such a block is not the database the connection reaches.
        if (isset($parsed['read']) && is_array($write)) {
            $parsed = array_merge($parsed, self::writeOverlay($parsed, $write));
        }

        /** @var array<string, mixed> */
        return Arr::except($parsed, ['read', 'write']);
    }

    /**
     * What the write side lays over the connection: the block, the one entry of a list, or what the
     * entries of a longer list agree on.
     *
     * `getReadWriteConfig()` takes `write` as a list when it has an entry `0` and picks one entry at
     * random. A key every entry agrees on is certain whichever it picks. Hosts that differ are a pool,
     * which is how the framework reads a host list anyway. Any other key the entries disagree on has
     * no single answer and keeps the connection's own value, because a list where the framework
     * expects one value would break every connection built from this configuration.
     *
     * @param  array<array-key, mixed>  $base
     * @param  array<array-key, mixed>  $write
     * @return array<array-key, mixed>
     */
    private static function writeOverlay(array $base, array $write): array
    {
        $entries = isset($write[0])
            ? array_values(array_filter($write, is_array(...)))
            : [$write];

        if (count($entries) < 2) {
            return $entries[0] ?? [];
        }

        $overlay = [];

        foreach (array_unique(array_merge(...array_map(array_keys(...), $entries))) as $key) {
            // An entry without the key inherits the connection's own value, as the merge does.
            $values = array_map(static fn (array $entry): mixed => array_key_exists($key, $entry) ? $entry[$key] : ($base[$key] ?? null), $entries);
            $distinct = array_values(array_unique(array_map(serialize(...), $values)));

            if (count($distinct) === 1) {
                $overlay[$key] = $values[0];
            } elseif ($key === 'host') {
                $overlay['host'] = array_values(array_unique(array_filter(Arr::flatten($values), is_string(...))));
            }
        }

        return $overlay;
    }

    /**
     * The config the framework MIGRATES through, which is not always the one it connects with.
     *
     * From Laravel 13.17 a PostgreSQL connection with a non-empty `direct` block runs its migrations
     * on `<name>::direct`: the block laid over the url-resolved base, the way the connection factory
     * builds it, so a pooled application account and a direct schema owner can be two different
     * roles. Without such a block, or on a framework that has no direct connection, migrations run
     * on the write side, which is {@see self::for()}.
     *
     * @return array<string, mixed>
     */
    public static function forMigrations(mixed $config): array
    {
        $parsed = self::withoutUrl($config);
        $direct = $parsed['direct'] ?? null;

        if (($parsed['driver'] ?? null) !== 'pgsql' || ! is_array($direct) || $direct === [] || ! self::frameworkMigratesDirect()) {
            return self::for($config);
        }

        // A list of direct endpoints is one the factory picks from at random. The first stands for
        // all of them here, because the question is which role migrates, and a list whose entries
        // named different roles would have no single answer to give.
        $block = array_is_list($direct) ? ($direct[0] ?? []) : $direct;

        /** @var array<string, mixed> $merged */
        $merged = Arr::except(array_merge($parsed, is_array($block) ? $block : []), [
            'read', 'write', 'direct', 'pooled', 'connect_via_database', 'connect_via_port',
        ]);

        return $merged;
    }

    /** Whether the installed framework routes migrations over a direct connection at all. */
    private static function frameworkMigratesDirect(): bool
    {
        return new ReflectionClass(Connection::class)->hasMethod('hasDirectConnection');
    }

    /**
     * The config with its `url` resolved into keys, the way the framework resolves it, and the
     * `read`/`write` split left as it was written.
     *
     * The URL's components come back as `driver`, `host`, `port`, `database` and the credentials,
     * laid over the keys they replace, and the `url` itself is gone. A caller that goes on to change
     * one of those keys therefore changes what the connection reaches.
     *
     * @return array<string, mixed>
     */
    public static function withoutUrl(mixed $config): array
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

        return $parsed;
    }

    /**
     * The config a catalog reading connects with: the URL resolved, the read/write split dropped,
     * and the host the run pinned, when it pinned one.
     *
     * The URL first, because the framework lays a `url`'s components over the keys, `host` among
     * them, so a host pinned beside a `url` would be replaced by the URL's. The split is dropped
     * because a catalog audit is a statement about ONE instance: a connection that sent reads to a
     * replica would produce a snapshot of a database nobody asked about. The pin replaces whatever
     * host remains, because a connection configured only through read/write blocks has no base host
     * at all, and without the pin it would reach whatever the driver defaults to.
     *
     * One place for every caller that has to reach what the audit read. The catalog reader connects
     * with it, and an external tool that judges the same database must be pointed at the same server,
     * or its findings sit beside the audit's about a database nobody named.
     *
     * @return array<string, mixed>
     */
    public static function forReading(mixed $config, ?string $pinnedHost = null): array
    {
        $settings = self::withoutUrl($config);

        unset($settings['read'], $settings['write']);

        if ($pinnedHost !== null) {
            $settings['host'] = $pinnedHost;
        }

        return $settings;
    }

    /**
     * The same connection pointed at another database on its server.
     *
     * When the framework builds a connection it lays a `url`'s components over the keys, `database`
     * among them. A `database` written beside a `url` therefore names a database the connection
     * never reaches: it lands in the one the URL names. Every throwaway database this package creates
     * is reached through a connection built here, so the URL is resolved first and the database set
     * last, and the name given is the database the connection reaches.
     *
     * @return array<string, mixed>
     */
    public static function onDatabase(mixed $config, string $database): array
    {
        return [...self::withoutUrl($config), 'database' => $database];
    }

    /**
     * The driver of a named connection, read the way Laravel reads it.
     *
     * The one call every reader in this package makes for this. `database.connections.<name>.driver`
     * is absent on a `url`-configured connection — the form Laravel Cloud, Heroku and every
     * `DATABASE_URL` deployment produce — because the framework derives the driver from the URL's
     * scheme at `ConfigurationUrlParser`. Reading the key raw answers `null` there, and the same
     * configuration would work under one command and fail under another.
     *
     * Taking the repository rather than the array, so a caller cannot get the path wrong either.
     */
    public static function driverForConnection(Repository $config, string $connection): ?string
    {
        return self::driverFor($config->get('database.connections.'.$connection));
    }

    /** The driver this connection resolves to, or null when it names none. */
    public static function driverFor(mixed $config): ?string
    {
        $driver = self::for($config)['driver'] ?? null;

        return is_string($driver) && $driver !== '' ? $driver : null;
    }
}
