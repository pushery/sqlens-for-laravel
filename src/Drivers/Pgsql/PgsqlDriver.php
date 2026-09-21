<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql;

use Pushery\SQLens\Contracts\AcceptsRunClock;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Docs\DocumentationSite;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\ExpectedTimeouts;
use Pushery\SQLens\Drivers\Pgsql\Rules\PgsqlRuleSet;
use Pushery\SQLens\Rules\Convention\NamingConvention;
use Pushery\SQLens\Rules\Lifecycle\LifecycleRuleSet;
use Pushery\SQLens\Rules\Money\MoneyColumnDictionary;
use Pushery\SQLens\Rules\Pedantic\DocumentationPolicy;
use Pushery\SQLens\Rules\Security\SecurityRuleSet;
use Pushery\SQLens\Security\Advisory\EolRepository;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Security\Privacy\UnencryptedColumnEvaluator;
use Pushery\SQLens\Today;
use Pushery\SQLens\Tools\Pgls\PglsTool;
use Pushery\SQLens\Tools\Squawk\SquawkTool;
use Pushery\SQLens\Tools\Tool;

/**
 * The PostgreSQL driver — its identity (key, name, version floor, docs) and its
 * lint rule pack. Readers (live-catalog) arrive later.
 *
 * Cross-import rule (enforced by an architecture test, stated here at the site of
 * temptation): nothing under Drivers\Pgsql may import Drivers\Mysql, and vice
 * versa. The two drivers never know about each other — that isolation is the
 * insurance for the later core+driver split, and it must never hold "only almost".
 */
final class PgsqlDriver implements AcceptsRunClock, Driver
{
    /**
     * @param  string  $projectRoot  so a rule's finding location is repo-relative; the
     *                               registry supplies the application base path, and the
     *                               empty default keeps a bare `new PgsqlDriver` (identity
     *                               only, no rule run) constructible in a test.
     * @param  ExpectedTimeouts|null  $expectedTimeouts  the project's configured timeout
     *                                                   requirement, read from config at the
     *                                                   registry; null defaults to both
     *                                                   timeouts, the shipped strict position.
     * @param  string|null  $uuidGeneratedBy  what the project declared about who produces a UUID
     *                                        primary key — `app`, `server`, or null when it has not
     *                                        said. Forwarded raw: the rule owns the vocabulary.
     * @param  int  $maxLocksPerTransaction  the project's configured single-transaction lock
     *                                       threshold (`pgsql.max_locks_per_transaction`);
     *                                       defaults to the shipped 1.
     */
    public function __construct(private readonly string $projectRoot = '', private readonly ?ExpectedTimeouts $expectedTimeouts = null, private readonly int $maxLocksPerTransaction = 1, private readonly ?string $uuidGeneratedBy = null, private readonly ?MoneyColumnDictionary $moneyColumns = null, private readonly ?int $unusedIndexMinDays = null,
        /**
         * The end-of-life data the patch-currency rules judge against, and today's date.
         *
         * Built once by the container and handed down rather than reached for, the same way every
         * other shared collaborator here arrives: a rule that read configuration would have a
         * verdict its own tests cannot see, and two rules reading the same file would eventually
         * disagree about what a malformed one means. Null falls back to the bundled copy, which is
         * what an unconfigured project reads anyway.
         */
        private readonly ?EolRepository $advisories = null,
        /**
         * The run's day, handed down by the runner through {@see self::withRunClock()}.
         *
         * Null is the documented fallback and stays so: `SecurityRuleSet::forProjectRoot()` then
         * resolves one reading per `rules()` call, which is what every driver did before the run
         * clock existed and what a third-party driver without the interface still gets.
         */
        private ?Today $today = null,
        /**
         * Which environment this run is looking at, for the privacy rules.
         *
         * Handed down like every other shared collaborator, and deliberately WITHOUT a
         * fallback: there is no honest default for "is this production", and a rule that
         * guessed would report a pass about a server nobody placed. Absent, the privacy
         * rules answer `undetermined`.
         */
        private readonly ?RunEnvironment $environment = null,
        /**
         * The privacy pack's column reading, built where a container is in reach.
         *
         * Optional and absent by default, exactly like $environment above: this namespace is
         * framework-free, and a reading that discovers models off the filesystem cannot be built
         * here. Absent, SEC.PII.UNENCRYPTED_COLUMN answers undetermined rather than nothing.
         */
        private readonly ?UnencryptedColumnEvaluator $privacyColumns = null,
        /**
         * The identifier convention the project configured, or the shipped one.
         *
         * Handed down like every other collaborator here rather than read: there are two naming
         * rules, one per engine, and they share one judgment — so a rule reading configuration
         * would give this package two places that could disagree about the same key.
         */
        private readonly ?NamingConvention $naming = null,
        /**
         * What the project asked to be documented, built once for the same reason as the naming
         * convention beside it: two engines share one comment rule, and a rule that read
         * configuration would have a verdict its own tests cannot see.
         */
        private readonly ?DocumentationPolicy $documentation = null,
        /**
         * The application's `database.migrations.table`, so the one table Laravel creates for
         * itself is not judged by a rule an application cannot act on. Null reads as Laravel's own
         * default, which is what an unconfigured project has anyway.
         */
        private readonly ?string $migrationsTable = null) {}

    public function key(): string
    {
        return 'pgsql';
    }

    public function displayName(): string
    {
        return 'PostgreSQL';
    }

    public function minimumServerVersion(): string
    {
        return '18';
    }

    public function documentationUrl(): string
    {
        return DocumentationSite::page('drivers/pgsql');
    }

    /**
     * The PostgreSQL lint rule pack, in the rule set's deterministic order.
     *
     * @return iterable<Rule>
     */
    public function rules(): iterable
    {
        // The engine-specific PostgreSQL pack, then the driver-neutral lifecycle rules
        // appended from their single Core source — the same composition the fixture suite
        // judges against, so production and the tests run the very same objects.
        return [
            ...PgsqlRuleSet::forProjectRoot($this->projectRoot, $this->expectedTimeouts, $this->maxLocksPerTransaction, $this->uuidGeneratedBy, $this->moneyColumns, $this->unusedIndexMinDays, $this->naming, $this->documentation, $this->migrationsTable)->all(),
            ...LifecycleRuleSet::forProjectRoot($this->projectRoot)->all(),
            // …and the security family, from the same kind of single Core source. It is appended here
            // rather than folded into the pack above because a security rule is weighed on the
            // SEVERITY axis: inside the pack it would sit in a set whose contract is the level gate.
            ...SecurityRuleSet::forProjectRoot($this->projectRoot, $this->advisories, $this->today?->value, $this->environment, $this->privacyColumns)->all(),
        ];
    }

    /**
     * A copy of this driver whose rules judge on the RUN's day.
     *
     * ⚠️ `clone` PLUS AN ASSIGNMENT, NOT `clone($this, [...])`, AND NOT A CONSTRUCTOR CALL. The
     * clone-with form reads better and is **PHP 8.5**; this package declares `php: ^8.4`, and the
     * development machine happens to run 8.5 — so `php -l` and a local Pint both accepted it and the
     * CI, on 8.4, answered with a parse error. A local syntax check measures the machine, not the
     * floor the package promises.
     *
     * A constructor call re-passing every promoted parameter is the other 8.4-safe shape, and it is
     * worse: thirteen arguments here, twelve next door, and a wither that rebuilds by hand silently
     * drops the next parameter somebody adds. Cloning copies every other field by construction.
     *
     * That is why the class-level `readonly` is gone and each property carries its own instead: a
     * readonly CLASS leaves no field a wither can write on 8.4. Every guarantee is kept except for
     * the one field this method exists to set.
     */
    public function withRunClock(Today $today): static
    {
        $clone = clone $this;
        $clone->today = $today;

        return $clone;
    }

    /**
     * Both shipped adapters, because both are PostgreSQL-only and say so themselves.
     *
     * Squawk parses migration FILES with libpg_query; the Postgres Language Server reads a LIVE
     * catalog. They serve different routes and neither replaces the other, which is why the list is
     * two entries rather than a choice.
     *
     * @return iterable<Tool>
     */
    public function tools(): iterable
    {
        return [new SquawkTool, new PglsTool];
    }
}
