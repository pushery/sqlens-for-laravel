<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Closure;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Contracts\DebtStandingResolvers;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\SessionDefense;
use Pushery\SQLens\Contracts\SessionDefenses;
use Pushery\SQLens\Deploy\Contracts\ResolvesDebtStanding;
use Pushery\SQLens\Deploy\UnaskableDebtStanding;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlSessionDefense;
use Pushery\SQLens\Drivers\Mysql\MysqlDriver;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlSessionDefense;
use Pushery\SQLens\Drivers\Pgsql\Deploy\PgsqlDebtStandingResolver;
use Pushery\SQLens\Drivers\Pgsql\PgsqlDriver;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\ExpectedTimeouts;
use Pushery\SQLens\Exceptions\InvalidDriverRegistration;
use Pushery\SQLens\Rules\Convention\NamingConvention;
use Pushery\SQLens\Rules\Money\MoneyColumnDictionary;
use Pushery\SQLens\Rules\Pedantic\DocumentationPolicy;
use Pushery\SQLens\Security\Advisory\EolRepository;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Security\Privacy\UnencryptedColumnEvaluator;

/**
 * The one place the mapping driver key → driver implementation lives, after the
 * Laravel manager pattern (custom creators). It is the only spot in the codebase
 * — with the service provider — allowed to name a concrete driver class; it hands
 * back only the Driver contract, never a concrete class, so driver isolation never
 * holds "only almost".
 *
 * The extension point takes NEW drivers; it never overwrites a core decision. A
 * duplicate key throws rather than silently overwriting. The reserved keys
 * (`mariadb`, `sqlite`, `sqlsrv`) are non-goals: extending them throws, so
 * the unsupported path can never be quietly bypassed — this is the ONE place the
 * blocklist lives. Resolution is lazy and deterministic (no class scans, no
 * autoload-order dependence).
 */
final class DriverRegistry implements DebtStandingResolvers, SessionDefenses
{
    /**
     * The seal a connection of this driver gets.
     *
     * It lives HERE rather than in a class of its own, and that is the whole point: exactly three
     * files in this package may know both engines, and the purity census pins them so a fourth
     * cannot slip in quietly. This registry is already one of the three — the mapping belongs beside
     * the other driver mappings rather than growing the set of files that carry engine knowledge.
     *
     * An unrecognized driver gets PostgreSQL's defense rather than none, and the asymmetry is
     * deliberate: a run reaches here only after the driver was accepted upstream, so an unknown one
     * is a wiring bug in this package. A null seal would open an UNSEALED session against a
     * production database at deploy time — the one thing this package promises never to do. The
     * wrong defense fails loudly on its first statement instead, and a wiring bug that shouts is one
     * somebody fixes.
     */
    public function for(string $driver): SessionDefense
    {
        return $driver === 'mysql' ? new MysqlSessionDefense : new PgsqlSessionDefense;
    }

    /**
     * The catalog question a recorded debt gets on this engine.
     *
     * Here for the same reason the seal above is: this file is already one of the three allowed to
     * know both engines, and a fourth would grow the set the purity census exists to bound.
     *
     * An engine with no resolver gets one that answers `ObjectNotFound` to everything, and the
     * asymmetry with the seal above is deliberate. A wrong SEAL fails loudly on its first statement,
     * so guessing there is safe. A wrong ANSWER about a debt is silent — it would report a paid
     * debt on an engine this build cannot even ask — so the honest reply is that the question stays
     * open, which is exactly what `ObjectNotFound` means and is reported with its own named reason.
     *
     * @param  list<string>  $stillOwed
     */
    public function debtStandingResolverFor(string $driver, array $stillOwed, ReaderSession $session): ResolvesDebtStanding
    {
        return $driver === 'pgsql'
            ? new PgsqlDebtStandingResolver($stillOwed, $session)
            : new UnaskableDebtStanding;
    }

    /** The non-goal engine keys that must fall through to the unsupported path — never extendable. */
    private const array RESERVED_KEYS = ['mariadb', 'sqlite', 'sqlsrv'];

    /** @var array<string, Closure(): Driver> */
    private array $creators = [];

    /** @var array<string, Driver> lazily instantiated, cached */
    private array $resolved = [];

    /**
     * ONE docblock, in constructor-parameter order. It used to be two stacked ones, and PHP attaches
     * only the LAST — so the three `@param` lines that stood above the second block documented
     * nothing any tool could read, and a static analyzer saw those parameters as undescribed.
     *
     * @param  string  $projectRoot  the application base path, threaded to the drivers so
     *                               their rules render repo-relative finding locations. The
     *                               empty default keeps a bare `new DriverRegistry()`
     *                               constructible where only key resolution is exercised.
     * @param  mixed  $pgsqlExpectedTimeouts  the raw `sqlens.pgsql.expected_timeouts` config
     *                                        value, narrowed to an {@see ExpectedTimeouts} here
     *                                        — this is the composition root, the one place
     *                                        allowed to name a concrete driver and hand it its
     *                                        engine-specific config. Null (the test default)
     *                                        means the shipped strict default of both timeouts.
     * @param  mixed  $pgsqlMaxLocksPerTransaction  the raw `sqlens.pgsql.max_locks_per_transaction`
     *                                              config value; a positive int, defaulting to the
     *                                              shipped 1 when absent or not an int (the config
     *                                              schema has already rejected a bad value by here).
     * @param  mixed  $auditExpect  the raw `sqlens.audit.expect` array — what the project states it
     *                              wants for the settings SQLens declines to have an opinion about.
     *                              Absent or malformed reads as "stated nothing", which is the
     *                              shipped default and silences only the expectation-based trigger.
     * @param  mixed  $uuidGeneratedBy  the raw `sqlens.audit.uuid_generated_by` value — `app`,
     *                                  `server`, or anything else, which reads as "not said".
     */
    public function __construct(private readonly string $projectRoot = '', mixed $pgsqlExpectedTimeouts = null, mixed $pgsqlMaxLocksPerTransaction = null, mixed $auditExpect = null, mixed $uuidGeneratedBy = null, mixed $moneyColumns = null, mixed $unusedIndex = null, mixed $naming = null, mixed $documentationConfig = null, private readonly ?EolRepository $advisories = null, private readonly ?string $today = null, private readonly ?UnencryptedColumnEvaluator $privacyColumns = null, private readonly ?RunEnvironment $environment = null)
    {
        // Built ONCE here and handed to both drivers, rather than each rule reading the config for
        // itself. A rule that read configuration would be a rule whose verdict depends on something
        // its own tests cannot see, and two rules reading the same key would eventually disagree
        // about what a malformed value means.
        $dictionary = MoneyColumnDictionary::bundled(
            $this->stringList(is_array($moneyColumns) ? ($moneyColumns['extra'] ?? null) : null),
            $this->stringList(is_array($moneyColumns) ? ($moneyColumns['ignore'] ?? null) : null),
        );

        // Built ONCE here for the same reason the dictionary above is: there are TWO naming rules,
        // one per engine, sharing one judgment — so there is exactly one place this may be built,
        // and neither rule reads configuration it could then disagree about.
        $convention = NamingConvention::fromConfig($naming);

        // Built ONCE here for the same reason, and with one more of its own: reading it inside a
        // rule would put `config()` into shipped code, which this package does not declare a
        // dependency for — a guard reads the source for exactly that helper.
        $documentation = DocumentationPolicy::fromConfig($documentationConfig);

        $expectedTimeouts = $pgsqlExpectedTimeouts === null
            ? ExpectedTimeouts::all()
            : ExpectedTimeouts::fromConfig($pgsqlExpectedTimeouts);

        $maxLocks = is_int($pgsqlMaxLocksPerTransaction) && $pgsqlMaxLocksPerTransaction >= 1
            ? $pgsqlMaxLocksPerTransaction
            : 1;

        // Narrowed here rather than trusted: the value reaches a rule that changes its VERDICT on
        // it, and anything but the two words it knows must read as "the project has not said". The
        // config validator already refuses a third word — this is the second line, for a registry
        // built directly in a test or by a consuming application.
        $uuid = in_array($uuidGeneratedBy, ['app', 'server'], true) ? $uuidGeneratedBy : null;

        // Narrowed here for the same reason as every other raw value: the config validator has
        // already refused a bad one, and this is the second line for a registry built in a test or
        // by a consuming application. Anything unusable reads as "the project has not said", which
        // is the shipped default rather than a zero — and a zero would mean "report on whatever
        // window exists", the one reading nobody should get by accident.
        $days = is_int($unusedIndexDays = (is_array($unusedIndex) ? ($unusedIndex['min_observation_days'] ?? null) : null))
            && $unusedIndexDays >= 0
                ? $unusedIndexDays
                : null;

        $this->register('pgsql', fn (): Driver => new PgsqlDriver($this->projectRoot, $expectedTimeouts, $maxLocks, $uuid, $dictionary, $days, $this->advisories, $this->today, $this->environment, $this->privacyColumns, $convention, $documentation));
        // Narrowed to string keys rather than asserted: `is_array()` admits a LIST, and the
        // driver's contract is a keyed map. A numerically-keyed entry under `audit.expect` names no
        // setting and cannot mean anything, so dropping it is the honest reading — and the config
        // validator has already refused a malformed shape by the time this runs.
        $expect = [];

        foreach (is_array($auditExpect) ? $auditExpect : [] as $key => $value) {
            if (is_string($key)) {
                $expect[$key] = $value;
            }
        }

        $this->register('mysql', fn (): Driver => new MysqlDriver($this->projectRoot, $expect, $dictionary, $days, $this->advisories, $this->today, $this->environment, $this->privacyColumns, $convention, $documentation));
    }

    /**
     * The usable strings in a configured list, and nothing else.
     *
     * A non-string entry names no column term and cannot mean anything, so it is dropped rather
     * than cast: the config validator has already refused a malformed shape by the time this runs,
     * and casting here would invent a term nobody wrote.
     *
     * @return list<string>
     */
    private function stringList(mixed $value): array
    {
        $strings = [];

        foreach (is_array($value) ? $value : [] as $item) {
            if (is_string($item) && trim($item) !== '') {
                $strings[] = $item;
            }
        }

        return $strings;
    }

    /**
     * Register a NEW third-party driver. Throws for a reserved key or a key that
     * is already taken — never a silent overwrite.
     *
     * @param  Closure(): Driver  $creator
     */
    public function extend(string $key, Closure $creator): void
    {
        if (in_array($key, self::RESERVED_KEYS, true)) {
            throw InvalidDriverRegistration::reservedKey($key);
        }

        $this->register($key, $creator);
    }

    /**
     * Whether a key is a reserved non-goal engine (`mariadb`/`sqlite`/`sqlsrv`).
     * This is the ONE source of the blocklist: the manager asks here to tell a
     * reserved driver apart from a genuinely unknown one, rather than keeping its
     * own copy.
     */
    public function isReserved(string $key): bool
    {
        return in_array($key, self::RESERVED_KEYS, true);
    }

    /** Resolve a driver by key, lazily instantiating it once. Null for an unknown key. */
    public function resolve(string $key): ?Driver
    {
        if (! isset($this->creators[$key])) {
            return null;
        }

        return $this->instantiate($key);
    }

    /**
     * Every registered driver, in the same deterministic order {@see self::keys()} defines.
     *
     * Exists so a caller that wants them ALL — the rule-registry export is the first — does not
     * have to walk the keys and re-check a null that cannot happen: a key from `keys()` always
     * resolves, and a null branch nothing can reach is a branch nothing can test.
     *
     * @return list<Driver>
     */
    public function all(): array
    {
        return array_map($this->instantiate(...), $this->keys());
    }

    /** Instantiate once and remember — the memoization both accessors share. */
    private function instantiate(string $key): Driver
    {
        return $this->resolved[$key] ??= ($this->creators[$key])();
    }

    /**
     * The registered keys in a deterministic (sorted) order — reporter and doc
     * output derive from this, so it must not depend on registration order.
     *
     * @return list<string>
     */
    public function keys(): array
    {
        $keys = array_keys($this->creators);
        sort($keys);

        return $keys;
    }

    /**
     * @param  Closure(): Driver  $creator
     */
    private function register(string $key, Closure $creator): void
    {
        if (isset($this->creators[$key])) {
            throw InvalidDriverRegistration::duplicateKey($key);
        }

        $this->creators[$key] = $creator;
    }
}
