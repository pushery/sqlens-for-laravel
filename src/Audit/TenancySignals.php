<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

/**
 * Whether this project looks like a multi-tenant one — asked of the configuration, never of a
 * database, and answered conservatively on purpose.
 *
 * ## Why the question has to be asked at all
 *
 * "Audit the database" is ambiguous the moment there is more than one tenant database. A report
 * produced from whichever connection happened to be default describes ONE tenant, and it is
 * indistinguishable from a report about the application — same header, same findings, same exit
 * code. The reader draws a conclusion about their system from a statement about one of its
 * customers.
 *
 * SQLens does not resolve that quietly. It asks the project to say which tenant its report is
 * about, and says so in the header. The alternative — looping over tenant connections and merging
 * the results — is deliberately NOT built: an aggregate over tenants is a different kind of claim
 * (it would have to say which tenants disagreed and why), and building the loop without that would
 * produce a report nobody could act on.
 *
 * ## The signals, and why each one is narrow
 *
 * Every signal here is a fact somebody deliberately put in the configuration. None of them
 * inspects a database, none guesses from a table name, and none fires on an ordinary application:
 *
 * - **Sibling connections on one driver with a shared prefix.** `tenant_eu`, `tenant_us` is a
 *   tenancy shape; `pgsql` + `mysql` is an ordinary app with two engines, and the driver check is
 *   what keeps the two apart. Two connections are not enough on their own — almost every Laravel
 *   app has `pgsql` and `sqlite` — so a shared NAME prefix is required as well.
 * - **A configured tenant database prefix.** A project that set one has already told us.
 * - **A known tenancy package in `composer.json`.** The most direct statement there is.
 *
 * ## It reports, it does not decide
 *
 * A signal means "say which tenant you mean", never "this project is multi-tenant, act
 * accordingly". The distinction matters because the heuristic is allowed to be wrong: a false
 * positive costs one config line, and a false negative costs nothing this class was going to
 * prevent. Anything stronger — refusing to run, picking a tenant, changing what is audited — would
 * make a guess load-bearing.
 */
final readonly class TenancySignals
{
    /**
     * Packages whose presence IS the statement.
     *
     * A short list rather than a pattern: matching `*tenan*` would fire on a package that merely
     * mentions tenants in its name, and the cost of a wrong hit here is an error message about a
     * setup the project does not have.
     *
     * @var list<string>
     */
    private const array PACKAGES = [
        'stancl/tenancy',
        'spatie/laravel-multitenancy',
        'tenancy/tenancy',
        'hyn/multi-tenant',
    ];

    /** @param  list<string>  $signals  what was found, in a stable order */
    private function __construct(public array $signals) {}

    /**
     * Read the signals out of a project's configuration.
     *
     * Both arrays are typed with `array-key` rather than `string`: they come from a config file and
     * from somebody's composer.json, so a narrower annotation would assert something about a file
     * this package does not own — and the runtime checks that make it true would then be removed
     * as redundant.
     *
     * @param  array<array-key, mixed>  $connections  `database.connections`, as configured
     * @param  array<array-key, mixed>  $composerRequire  the `require` block of composer.json
     * @param  mixed  $tenantPrefix  a configured tenant database prefix, if the project set one
     */
    public static function detect(array $connections, array $composerRequire = [], mixed $tenantPrefix = null): self
    {
        $signals = [];

        $siblings = self::siblingConnections($connections);

        if ($siblings !== null) {
            $signals[] = sprintf('several connections on one driver share the name prefix "%s"', $siblings);
        }

        if (is_string($tenantPrefix) && trim($tenantPrefix) !== '') {
            $signals[] = 'a tenant database prefix is configured';
        }

        foreach (self::PACKAGES as $package) {
            if (array_key_exists($package, $composerRequire)) {
                $signals[] = sprintf('the tenancy package %s is installed', $package);
            }
        }

        return new self($signals);
    }

    /** No signals at all — the ordinary case, and the one that needs no configuration. */
    public static function none(): self
    {
        return new self([]);
    }

    public function found(): bool
    {
        return $this->signals !== [];
    }

    /** The signals as one sentence, for a message that has to explain itself. */
    public function describe(): string
    {
        return implode('; ', $this->signals);
    }

    /**
     * Whether this connection is another one's offspring rather than its sibling.
     *
     * The distinction the first version of this class missed, and it cost a false positive on the
     * package's own test suite: a fixture creates `cross_db_test::pgsql_fixture_ddl` beside
     * `cross_db_test`, both on PostgreSQL, and the shared-prefix rule read them as two tenants.
     * They are one connection and a helper derived from it.
     *
     * A tenancy set is siblings — `tenant_eu`, `tenant_us` — where no member's name contains
     * another's. A name that STARTS with another configured connection's name is that connection
     * extended for some purpose, a shape ordinary applications produce all the time and tenancy
     * does not.
     *
     * @param  list<string>  $names  every configured connection name
     */
    private static function isDerivedFrom(string $name, array $names): bool
    {
        return array_any($names, fn (string $other): bool => $other !== $name && $other !== '' && str_starts_with($name, $other));
    }

    /**
     * The name prefix shared by two or more connections ON THE SAME DRIVER, or null.
     *
     * Both halves are load-bearing. The DRIVER check is what stops `pgsql` + `mysql` — an ordinary
     * app with two engines — from reading as tenancy. The shared PREFIX is what stops two unrelated
     * connections on one driver from qualifying: a tenancy setup names its connections after a
     * scheme, and `pgsql` beside `reporting` does not follow one.
     *
     * A prefix is the part before the first underscore, and at least two characters, so a pair
     * like `a_x` and `b_y` cannot produce a one-letter "scheme" that means nothing.
     *
     * The key type is `array-key`, not `string`, and the runtime check below stays. The array comes
     * from `config('database.connections')`, which is whatever the application put there — a
     * narrower annotation would be an assertion about somebody else's file, and PHPStan would then
     * remove the one check that makes it true.
     *
     * @param  array<array-key, mixed>  $connections
     */
    private static function siblingConnections(array $connections): ?string
    {
        /** @var array<string, array<string, int>> $byDriverAndPrefix */
        $byDriverAndPrefix = [];

        $names = array_values(array_filter(array_keys($connections), is_string(...)));

        foreach ($connections as $name => $config) {
            if (is_string($name) && self::isDerivedFrom($name, $names)) {
                continue;
            }

            if (! is_string($name)) {
                continue;
            }
            if (! is_array($config)) {
                continue;
            }
            if (! is_string($driver = $config['driver'] ?? null)) {
                continue;
            }
            $underscore = strpos($name, '_');
            if ($underscore === false) {
                continue;
            }
            if ($underscore < 2) {
                continue;
            }

            $prefix = substr($name, 0, $underscore);
            $byDriverAndPrefix[$driver][$prefix] = ($byDriverAndPrefix[$driver][$prefix] ?? 0) + 1;
        }

        // Sorted, so a project with two qualifying schemes always gets the same one named — the
        // message is part of a report, and a report that changes wording between runs over one
        // state is a determinism break like any other.
        ksort($byDriverAndPrefix);

        foreach ($byDriverAndPrefix as $prefixes) {
            ksort($prefixes);

            foreach ($prefixes as $prefix => $count) {
                if ($count >= 2) {
                    return (string) $prefix;
                }
            }
        }

        return null;
    }
}
