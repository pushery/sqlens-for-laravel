<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Which connection a preflight reads through, and the reason when there is none.
 *
 * ## Why this is not simply "the default connection"
 *
 * A preflight runs beside a deploy, so the connection nearest to hand is the one that runs the
 * migrations — and that role holds `ALTER` and `DROP` on the application's schema. Reading through
 * it works perfectly. It also quietly breaks the least-privilege promise this package makes about
 * itself, and it breaks it in the only way that is hard to notice: **everything stays green.**
 *
 * That matters more here than it would in most tools. A package that audits security and reads with
 * more privilege than it needs has spent the credibility it is selling. So the fallback chain stops
 * rather than reaching for the powerful connection: a configured preflight connection, then the
 * audit connection, then a NAMED skip that says what to configure.
 *
 * ## The case that is allowed but must not be silent
 *
 * On a small project the preflight connection and the migration connection are genuinely the same,
 * and refusing to run there would make the feature unusable for the people who need it most. So it
 * runs — and says so. The difference between "this is fine for you" and "nobody noticed" is a
 * sentence in the report, and this class is where that sentence comes from.
 */
final readonly class PreflightConnection
{
    private function __construct(
        /** The Laravel connection name to read through, or null when none could be resolved. */
        public ?string $name,
        /** Why there is none — present exactly when `$name` is null. */
        public ?CatalogSkip $skip,
        /** Whether the resolved connection is the one that runs migrations. */
        public bool $sharesMigrationConnection,
        /**
         * The database ROLE the migrations run as, or null when the configuration does not say.
         *
         * The role rather than the connection name, because that is what a grant check hands to the
         * database: `has_table_privilege(<role>, …)` takes a role, and a connection name means
         * nothing to a server.
         *
         * Null and never `''`. An environment-driven configuration with an unfilled `DB_USERNAME`
         * produces an empty string, and two empty role names compare EQUAL — a check asking "may
         * `''` alter this table" would certify a role that does not exist. The same trap is already
         * pinned one layer up in `AuditRunner::connectionIdentity()`.
         */
        public ?string $migrationRole = null,
    ) {}

    /**
     * Resolve the connection a preflight may read through.
     *
     * The chain is short and every link is deliberate:
     *
     * 1. `sqlens.preflight.connection` — a connection NAME, never credentials. Credentials in a
     *    package config end up in a repository, and a read-only role's password is still a password.
     * 2. `sqlens.connection` — the audit connection, when one is configured. A project that already
     *    told this package which connection to read has answered the question once.
     * 3. Nothing. NOT `database.default`, and that is the whole point: falling through to it is
     *    exactly the silent use of the migration connection this ticket exists to prevent.
     */
    public static function resolve(Repository $config): self
    {
        $migration = self::migrationConnectionName($config);
        $role = self::roleOf($config, $migration);

        $configured = $config->get('sqlens.preflight.connection');

        if (is_string($configured) && $configured !== '') {
            return self::named($configured, $config, $migration, $role);
        }

        $audit = $config->get('sqlens.connection');

        if (is_string($audit) && $audit !== '') {
            return self::named($audit, $config, $migration, $role);
        }

        return new self(null, CatalogSkip::for(
            SchemaObjectType::Database,
            'preflight connection',
            SkipReason::NotReadable,
            'no preflight connection is configured, and this reading will not fall back to the '
            .'connection that runs your migrations. That role holds ALTER and DROP on your schema, '
            .'and a preflight reading through it would break the least-privilege promise silently — '
            .'everything would stay green. Configure `sqlens.preflight.connection` with the NAME of '
            .'a read-only connection, or `sqlens.connection` if one connection is all this project '
            .'has.',
        ), false);
    }

    /**
     * The role a connection logs in as, or null when the configuration does not say.
     *
     * Empty is null, deliberately — see the property note. A blank username is what an unfilled
     * environment variable interpolates to, and it is the common case rather than an exotic one.
     */
    private static function roleOf(Repository $config, string $connection): ?string
    {
        $username = $config->get('database.connections.'.$connection.'.username');

        return is_string($username) && $username !== '' ? $username : null;
    }

    /** Whether a reading can happen at all. */
    public function isResolved(): bool
    {
        return $this->name !== null;
    }

    /**
     * The advisory for a preflight that is reading through the migration connection.
     *
     * A skip would be wrong: the reading HAPPENED and its results are good. What is not good is the
     * privilege it used, and that is a fact about the project's configuration rather than about the
     * database — so it is a named note rather than a gap, and it never makes a snapshot partial.
     */
    public function advisory(): ?CatalogSkip
    {
        if (! $this->sharesMigrationConnection || $this->name === null) {
            return null;
        }

        return CatalogSkip::for(
            SchemaObjectType::Database,
            $this->name,
            SkipReason::ExcludedByConfig,
            sprintf(
                'this preflight read through "%s", which is also the connection that runs your '
                .'migrations — so it read with ALTER and DROP rights it never needs. The reading '
                .'itself is complete and correct; what is missing is the separation. Give the '
                .'preflight its own read-only connection and name it in '
                .'`sqlens.preflight.connection`.',
                $this->name,
            ),
        );
    }

    private static function named(string $name, Repository $config, string $migration, ?string $role): self
    {
        // A configured name that resolves to nothing is a typo, and a typo must not degrade into
        // the default connection — that is the same silent fallback by another road.
        if (! is_array($config->get('database.connections.'.$name))) {
            return new self(null, CatalogSkip::for(
                SchemaObjectType::Database,
                $name,
                SkipReason::NotReadable,
                sprintf(
                    'the configured preflight connection "%s" is not a connection this application '
                    .'defines. Nothing was read: falling back to the default connection here would '
                    .'turn a typo into a preflight running with migration rights, which is the one '
                    .'outcome this resolution exists to prevent.',
                    $name,
                ),
            ), false);
        }

        return new self($name, null, $name === $migration, $role);
    }

    /**
     * The connection migrations run on.
     *
     * `database.migrations.connection` when the application sets it, and the default otherwise —
     * which is what Laravel itself does. Reading only the first would report every ordinary project
     * as separated, because most never set it.
     */
    private static function migrationConnectionName(Repository $config): string
    {
        // This package already asks a project which connection runs its migrations — the security
        // rules about DDL privilege are built on that answer. Asking again in a second key would
        // create two places that can disagree, and the one nobody updated would win silently.
        $declared = $config->get('sqlens.security.migration_connection');

        if (is_string($declared) && $declared !== '') {
            return $declared;
        }

        $configured = $config->get('database.migrations.connection');

        if (is_string($configured) && $configured !== '') {
            return $configured;
        }

        $default = $config->get('database.default');

        // An application with no default at all is a real state, and answering with the empty
        // string is the honest one: nothing can equal it, so no connection is reported as sharing a
        // migration connection that does not exist.
        return is_string($default) ? $default : '';
    }
}
