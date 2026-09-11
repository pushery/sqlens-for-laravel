<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql;

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
final readonly class PgsqlDriver implements Driver
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
    public function __construct(private string $projectRoot = '', private ?ExpectedTimeouts $expectedTimeouts = null, private int $maxLocksPerTransaction = 1, private ?string $uuidGeneratedBy = null, private ?MoneyColumnDictionary $moneyColumns = null, private ?int $unusedIndexMinDays = null,
        /**
         * The end-of-life data the patch-currency rules judge against, and today's date.
         *
         * Built once by the container and handed down rather than reached for, the same way every
         * other shared collaborator here arrives: a rule that read configuration would have a
         * verdict its own tests cannot see, and two rules reading the same file would eventually
         * disagree about what a malformed one means. Null falls back to the bundled copy, which is
         * what an unconfigured project reads anyway.
         */
        private ?EolRepository $advisories = null,
        /** ISO-8601. Null reads the clock ONCE, here, rather than once per rule across midnight. */
        private ?string $today = null,
        /**
         * Which environment this run is looking at, for the privacy rules.
         *
         * Handed down like every other shared collaborator, and deliberately WITHOUT a
         * fallback: there is no honest default for "is this production", and a rule that
         * guessed would report a pass about a server nobody placed. Absent, the privacy
         * rules answer `undetermined`.
         */
        private ?RunEnvironment $environment = null,
        /**
         * The privacy pack's column reading, built where a container is in reach.
         *
         * Optional and absent by default, exactly like $environment above: this namespace is
         * framework-free, and a reading that discovers models off the filesystem cannot be built
         * here. Absent, SEC.PII.UNENCRYPTED_COLUMN answers undetermined rather than nothing.
         */
        private ?UnencryptedColumnEvaluator $privacyColumns = null,
        /**
         * The identifier convention the project configured, or the shipped one.
         *
         * Handed down like every other collaborator here rather than read: there are two naming
         * rules, one per engine, and they share one judgment — so a rule reading configuration
         * would give this package two places that could disagree about the same key.
         */
        private ?NamingConvention $naming = null,
        /**
         * What the project asked to be documented, built once for the same reason as the naming
         * convention beside it: two engines share one comment rule, and a rule that read
         * configuration would have a verdict its own tests cannot see.
         */
        private ?DocumentationPolicy $documentation = null,
        /**
         * The application's `database.migrations.table`, so the one table Laravel creates for
         * itself is not judged by a rule an application cannot act on. Null reads as Laravel's own
         * default, which is what an unconfigured project has anyway.
         */
        private ?string $migrationsTable = null) {}

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
            ...SecurityRuleSet::forProjectRoot($this->projectRoot, $this->advisories, $this->today, $this->environment, $this->privacyColumns)->all(),
        ];
    }

    /**
     * Empty for now — the PostgreSQL catalog readers land later.
     *
     * @return iterable<object>
     */
    public function readers(): iterable
    {
        return [];
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
