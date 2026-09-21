<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql;

use Pushery\SQLens\Contracts\AcceptsRunClock;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Docs\DocumentationSite;
use Pushery\SQLens\Drivers\Mysql\Rules\MysqlRuleSet;
use Pushery\SQLens\Rules\Convention\NamingConvention;
use Pushery\SQLens\Rules\Lifecycle\LifecycleRuleSet;
use Pushery\SQLens\Rules\Money\MoneyColumnDictionary;
use Pushery\SQLens\Rules\Pedantic\DocumentationPolicy;
use Pushery\SQLens\Rules\Security\SecurityRuleSet;
use Pushery\SQLens\Security\Advisory\EolRepository;
use Pushery\SQLens\Security\Privacy\RunEnvironment;
use Pushery\SQLens\Security\Privacy\UnencryptedColumnEvaluator;
use Pushery\SQLens\Today;
use Pushery\SQLens\Tools\Tool;

/**
 * The MySQL driver — its identity (key, name, version floor, docs) and its lint rule
 * pack. Readers (live-catalog) arrive later.
 *
 * Cross-import rule (enforced by an architecture test, stated here at the site of
 * temptation): nothing under Drivers\Mysql may import Drivers\Pgsql, and vice
 * versa. The two drivers never know about each other — that isolation is the
 * insurance for the later core+driver split, and it must never hold "only almost".
 */
final class MysqlDriver implements AcceptsRunClock, Driver
{
    /**
     * @param  string  $projectRoot  so a rule's finding location is repo-relative; the registry
     *                               supplies the application base path, and the empty default
     *                               keeps a bare `new MysqlDriver` (identity only, no rule run)
     *                               constructible in a test.
     */
    public function __construct(private readonly string $projectRoot = '',
        /**
         * What the project stated it wants, from `sqlens.audit.expect` — for the settings where
         * SQLens deliberately has no opinion of its own.
         *
         * One array rather than one parameter per key: the next such setting would otherwise widen
         * this signature again, and a constructor that grows a parameter per rule has stopped being
         * a constructor.
         *
         * @var array<string, mixed>
         */
        private readonly array $auditExpect = [],
        /**
         * The money-column dictionary, already merged with the project's own terms.
         *
         * Handed in rather than read here, so a rule's verdict never depends on configuration its
         * own tests cannot see. Null means the shipped dictionary alone, which is what a bare
         * `new MysqlDriver` in a test wants.
         */
        private readonly ?MoneyColumnDictionary $moneyColumns = null,
        /** How long the counters must have run before an unused index is reported; null is the shipped default. */
        private readonly ?int $unusedIndexMinDays = null,
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
        /** Which environment this run is looking at — see PgsqlDriver for why it has no default. */
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
        return 'mysql';
    }

    public function displayName(): string
    {
        return 'MySQL';
    }

    public function minimumServerVersion(): string
    {
        return '8.4';
    }

    public function documentationUrl(): string
    {
        return DocumentationSite::page('drivers/mysql');
    }

    /**
     * The MySQL lint rule pack, in the rule set's deterministic order, then the driver-neutral
     * lifecycle rules — both routed through their own single source, so a rule is added in one
     * place and what a user runs is what the fixture suite judges.
     *
     * The lifecycle rules are the same objects the PostgreSQL driver serves, and they are appended
     * here rather than duplicated: a WHERE-less DELETE is a WHERE-less DELETE on either engine. What
     * is NOT shared is the proof — each of them carries its own MySQL fixture pair, because a rule
     * registered for one engine and not the other is invisible until somebody runs the other one.
     *
     * @return iterable<Rule>
     */
    public function rules(): iterable
    {
        return [
            ...MysqlRuleSet::shipped($this->projectRoot, $this->auditExpect, $this->moneyColumns, $this->unusedIndexMinDays, $this->naming, $this->documentation, $this->migrationsTable)->all(),
            ...LifecycleRuleSet::forProjectRoot($this->projectRoot)->all(),
            // …and the security family, the same Core source the PostgreSQL driver composes. It is
            // registered here even though its only rule today has nothing to say on MySQL: the rule
            // judges a GRANT subject, MySQL has no PUBLIC pseudo-role, and so it is silent as a matter
            // of DATA rather than of registration. That is the stronger arrangement — a per-driver
            // list would make "silent here" a line somebody has to remember to keep true.
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
     * None, and that is an answer rather than a gap.
     *
     * There is no MySQL equivalent of Squawk or the Postgres Language Server in this build. Saying
     * so here is what keeps the empty list from reading as "nobody filled this in yet".
     *
     * @return iterable<Tool>
     */
    public function tools(): iterable
    {
        return [];
    }
}
