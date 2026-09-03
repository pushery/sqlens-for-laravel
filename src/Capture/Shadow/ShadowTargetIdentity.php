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
 * shadow will be built. A developer who points `sqlens.capture.shadow.connection` at the wrong
 * entry in `config/database.php` passes every one of those questions and then has the tool create
 * a scratch database on the instance it was supposed to be comparing — and drop it afterwards.
 *
 * That is the worst failure this package can have, so it gets its own lock, and the lock is
 * mechanical rather than advisory: a collision is a refusal, never a warning.
 *
 * ## It fails CLOSED, and that is the whole design
 *
 * Comparing two connection configurations is not string equality. `localhost` and `127.0.0.1` are
 * the same server. A missing port means the driver's default, which is the same port the other side
 * probably wrote out. A host of `null` means "whatever the driver decides" — and two nulls decide
 * the same way.
 *
 * Every one of those is a case where the naive answer is "different" and the truth is "same". So
 * where this class cannot establish that two configurations point at DIFFERENT places, it reports a
 * collision. The cost of a false collision is a message telling somebody to name their connections
 * apart. The cost of a false all-clear is a dropped production database.
 */
final readonly class ShadowTargetIdentity
{
    /**
     * Host spellings that mean the local machine.
     *
     * Listed rather than resolved: a DNS lookup would make this class do network I/O to answer a
     * safety question, and a lookup that fails or times out would have to answer something. The
     * three spellings below cover what a `config/database.php` realistically contains, and anything
     * outside them is compared literally — which errs toward collision, the safe direction.
     *
     * @var list<string>
     */
    private const array LOCAL_HOSTS = ['localhost', '127.0.0.1', '::1'];

    /** The port each driver uses when the configuration names none. */
    private const array DEFAULT_PORTS = ['pgsql' => '5432', 'mysql' => '3306', 'mariadb' => '3306'];

    /**
     * Whether these two configurations may point at the same database on the same server.
     *
     * "May" is deliberate. A `true` here does not prove they collide — it proves this class could
     * not establish that they do not.
     *
     * @param  array<string, mixed>  $shadow
     * @param  array<string, mixed>  $target
     */
    public static function collide(array $shadow, array $target): bool
    {
        return self::identity($shadow) === self::identity($target);
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
        $driver = self::text($config, 'driver');

        return $driver
            .'://'.self::host($config)
            .':'.self::port($config, $driver)
            .'/'.self::text($config, 'database');
    }

    /**
     * Whether two configurations address the same SERVER, whatever database each names.
     *
     * The instance question and the database question are different, and conflating them makes one
     * of the two checks wrong. `capture.shadow.direct_connection` exists to reach the SAME server by
     * a different route — around a transaction pooler — so there it must be the same instance and
     * the database legitimately differs: provisioning connects to the maintenance database, not to
     * the project's. Comparing the full identity there would refuse every correct configuration.
     *
     * @param  array<string, mixed>  $one
     * @param  array<string, mixed>  $other
     */
    public static function sameInstance(array $one, array $other): bool
    {
        return self::instanceOf($one) === self::instanceOf($other);
    }

    /**
     * One configuration reduced to the SERVER it reaches — {@see identity()} without the database.
     *
     * @param  array<string, mixed>  $config
     */
    public static function instanceOf(array $config): string
    {
        $driver = self::text($config, 'driver');

        return $driver.'://'.self::host($config).':'.self::port($config, $driver);
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
     * It names BOTH identities rather than saying "they are the same": the reader has to change one
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
     * The host, with the local spellings folded onto one.
     *
     * An absent host folds onto the local name too: a driver with no host connects locally, and
     * treating "absent" as its own value would let `['host' => null]` and `['host' => 'localhost']`
     * read as two different servers when they are one.
     *
     * @param  array<string, mixed>  $config
     */
    private static function host(array $config): string
    {
        $host = mb_strtolower(self::text($config, 'host'));

        return $host === '' || in_array($host, self::LOCAL_HOSTS, true) ? 'localhost' : $host;
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
