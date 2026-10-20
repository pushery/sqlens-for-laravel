<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

/**
 * The second lock on the only path in this package that CREATES and DROPS databases.
 *
 * ## What it prevents, and why one lock was not enough
 *
 * {@see ProductionGuard} asks "may this mode run here at all" — environment, production flag,
 * confirmation. It answers correctly and it is not enough, because it never looks at WHERE the
 * shadow will be built. A developer who points `sqlens.capture.shadow.connection` at the entry of
 * the connection under examination passes every one of those questions, and the reference would
 * then be built in the very database it stands in for.
 *
 * That is the worst failure this package can have, so it gets its own lock, and the lock is
 * mechanical rather than advisory: a collision is a refusal, never a warning. What it refuses is
 * the same database on the same server. A shadow on the same server under another database
 * passes, because the provisioner names its throwaway database itself and drops only that one.
 *
 * ## Where it fails closed, and where it cannot
 *
 * Comparing two connection configurations is not string equality. `localhost` and `127.0.0.1` are
 * the same server. A missing port means the driver's default, which is the same port the other side
 * probably wrote out. A host of `null` means "whatever the driver decides" — and two nulls decide
 * the same way. A host list is a pool the framework picks one member of for each connection, so a
 * shadow pool that shares a member with the examined connection may land on it.
 *
 * Each of those is folded onto one answer, and a host of a shape this class cannot read collides
 * with everything. What it cannot fold without network I/O is an alias: a DNS name and the address
 * it resolves to, or a short name and its fully qualified one, compare as two servers. Resolving
 * them would make a safety question depend on a lookup that can fail or time out, so the limit is
 * stated here instead of guessed around.
 */
final readonly class ShadowTargetIdentity
{
    /**
     * Host spellings that mean the local machine.
     *
     * Listed rather than resolved: a DNS lookup would make this class do network I/O to answer a
     * safety question, and a lookup that fails or times out would have to answer something. The
     * three spellings below cover what a `config/database.php` realistically contains, and anything
     * outside them is compared literally, so an alias of one server reads as another server.
     *
     * @var list<string>
     */
    private const array LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1'];

    /** The port each driver uses when the configuration names none. */
    private const array DEFAULT_PORTS = ['pgsql' => '5432', 'mysql' => '3306', 'mariadb' => '3306'];

    /**
     * Whether these two configurations may point at the same database on the same server.
     *
     * "May" is deliberate. A `true` does not prove they collide: it holds wherever driver, port and
     * database agree and the hosts share a member, or one of the hosts cannot be read. A `false`
     * proves less than it says for an alias, which this class does not resolve.
     *
     * @param  array<string, mixed>  $shadow
     * @param  array<string, mixed>  $target
     */
    public static function collide(array $shadow, array $target): bool
    {
        if (self::endpoint($shadow).'/'.self::text($shadow, 'database') !== self::endpoint($target).'/'.self::text($target, 'database')) {
            return false;
        }

        $one = self::hosts($shadow);
        $other = self::hosts($target);

        return $one === null || $other === null || array_intersect($one, $other) !== [];
    }

    /**
     * One configuration reduced to what decides WHERE it writes.
     *
     * Driver included: `pgsql` and `mysql` on one host and one port are two different servers, and
     * a comparison that dropped the driver would call them the same.
     *
     * @param  array<string, mixed>  $config
     */
    public static function identity(array $config): string
    {
        return self::instanceOf($config).'/'.self::text($config, 'database');
    }

    /**
     * Whether two configurations address the same SERVER, whatever database each names.
     *
     * The instance question and the database question are different, and conflating them makes one
     * of the two checks wrong. `capture.shadow.direct_connection` exists to reach the same server by
     * a different route — around a transaction pooler — so there it must be the same instance and
     * the database legitimately differs: provisioning connects to the maintenance database, not to
     * the project's. Comparing the full identity there would refuse every correct configuration.
     *
     * Here the safe answer is "not the same", the reverse of {@see collide()}: a host pool is the same
     * server only as the same pool, and a host of a shape this class cannot read is never the same.
     *
     * @param  array<string, mixed>  $one
     * @param  array<string, mixed>  $other
     */
    public static function sameInstance(array $one, array $other): bool
    {
        $hosts = self::hosts($one);

        return $hosts !== null && $hosts === self::hosts($other) && self::endpoint($one) === self::endpoint($other);
    }

    /**
     * One configuration reduced to the SERVER it reaches — {@see identity()} without the database.
     *
     * @param  array<string, mixed>  $config
     */
    public static function instanceOf(array $config): string
    {
        $driver = self::text($config, 'driver');
        $hosts = self::hosts($config);

        return $driver.'://'.($hosts === null ? '?' : implode(',', $hosts)).':'.self::port($config, $driver);
    }

    /**
     * The sentence a refusal about the DIRECT connection carries.
     *
     * A different wording from {@see refusal()} because it is a different mistake with a different
     * fix. There the two must not be the same place; here they must — and a reader who was handed
     * the other sentence would go looking for a separation that is already correct.
     *
     * @param  array<string, mixed>  $direct
     * @param  array<string, mixed>  $source
     */
    public static function directConnectionRefusal(array $direct, array $source): string
    {
        // The wording avoids the literal SQL keywords on purpose, and it is not squeamishness: the
        // architecture guards scan STRING LITERALS for `CREATE DATABASE` / `DROP DATABASE` and
        // require every hit to live behind the driver provisioner boundary. A sentence that spelled
        // out what the mistake costs would put this file on that list — a false hit, in the guard
        // that protects the most dangerous operation the package has. Say it in words instead.
        return 'sqlens.capture.shadow.direct_connection addresses a different server ('
            .self::instanceOf($direct).') than the connection under examination ('
            .self::instanceOf($source).'). It exists to reach the SAME server around a transaction '
            .'pooler, so a different one would provision and tear down throwaway databases on an '
            .'instance this run never named. Point it at the same host and port, bypassing the '
            .'pooler.';
    }

    /**
     * The sentence a refusal carries.
     *
     * It names both identities rather than saying "they are the same": the reader has to change one
     * of two configuration entries, and which one is not obvious from a message that shows a single
     * value.
     *
     * @param  array<string, mixed>  $shadow
     * @param  array<string, mixed>  $target
     */
    public static function refusal(array $shadow, array $target): string
    {
        return 'the shadow connection resolves to the same place as the connection under '
            .'examination ('.self::identity($shadow).'), so building the reference there would '
            .'create and then DROP a database on the instance being compared. Point '
            .'sqlens.capture.shadow.connection at a separate server or a separate database. '
            .'Examined: '.self::identity($target);
    }

    /**
     * The hosts a configuration may reach, sorted, with the local spellings folded onto one, or null
     * when the value has a shape this class cannot read.
     *
     * An absent host folds onto the local name too: a driver with no host connects locally, and
     * treating "absent" as its own value would let `['host' => null]` and `['host' => 'localhost']`
     * read as two different servers when they are one. A list of names is a pool, read as the set
     * of its members, never as one of them and never as the local machine.
     *
     * @param  array<string, mixed>  $config
     * @return list<string>|null
     */
    private static function hosts(array $config): ?array
    {
        $value = $config['host'] ?? null;

        if ($value === null || is_scalar($value)) {
            return [self::folded((string) $value)];
        }

        if (! is_array($value) || $value === []) {
            return null;
        }

        $hosts = [];

        foreach ($value as $host) {
            if (! is_string($host)) {
                return null;
            }

            $hosts[] = self::folded($host);
        }

        $hosts = array_values(array_unique($hosts));
        sort($hosts);

        return $hosts;
    }

    /** One host name, with the local spellings folded onto one. */
    private static function folded(string $host): string
    {
        $host = mb_strtolower(trim($host));

        return $host === '' || in_array($host, self::LOCAL_HOSTS, true) ? 'localhost' : $host;
    }

    /**
     * The driver and the port, which with the hosts decide the server.
     *
     * @param  array<string, mixed>  $config
     */
    private static function endpoint(array $config): string
    {
        $driver = self::text($config, 'driver');

        return $driver.':'.self::port($config, $driver);
    }

    /**
     * The port, with the driver's default filled in.
     *
     * @param  array<string, mixed>  $config
     */
    private static function port(array $config, string $driver): string
    {
        $port = self::text($config, 'port');

        return $port === '' ? (self::DEFAULT_PORTS[$driver] ?? '') : $port;
    }

    /**
     * One configuration value as a string, whatever shape it arrived in.
     *
     * A port is an int in one project and a string in the next, because `.env` hands out strings
     * and a config file hands out literals. Comparing them by type would make `5432` and `'5432'`
     * two different servers — the unsafe direction.
     *
     * @param  array<string, mixed>  $config
     */
    private static function text(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        return is_scalar($value) ? mb_strtolower(trim((string) $value)) : '';
    }
}
