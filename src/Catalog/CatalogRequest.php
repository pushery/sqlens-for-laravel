<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * What a catalog reading was ASKED for — the scope, stated rather than assumed.
 *
 * Every field here exists because its absence is a documented way audits go wrong on real
 * databases. A reader that assumes `public`, assumes no table prefix, and assumes every object is
 * the user's own will, on a perfectly ordinary Laravel project, report an audit of the wrong half
 * of the schema and multiply its findings by the partition count. Those are not exotic setups;
 * they are Tuesday.
 *
 * The request is also what makes two readings COMPARABLE. A drift comparison between a snapshot
 * scoped to two schemas and one scoped to five is not a diff of the database, it is a diff of the
 * question — which is why the scope that was applied travels on the snapshot's context too.
 */
final readonly class CatalogRequest
{
    /**
     * @param  list<string>  $schemas  the schemas to read; empty means "whatever the reader resolves as
     *                                 the default scope" — the session's real `search_path` on
     *                                 PostgreSQL, the connection's database on MySQL. Empty is a
     *                                 deliberate deferral to the reader, not a wildcard.
     * @param  list<SchemaObjectType>  $types  the object types to read; empty means every type the
     *                                         reader supports. A narrow list is how a caller that
     *                                         needs one axis avoids paying for the whole catalog.
     */
    public function __construct(
        public array $schemas = [],
        public array $types = [],
        /**
         * The table prefix to strip when naming objects, `''` for none.
         *
         * Stripped rather than ignored: a user who set `prefix => 'acme_'` in Laravel thinks in
         * terms of `orders`, and a finding about `acme_orders` is a finding about a table they do
         * not believe they have.
         */
        public string $tablePrefix = '',
        /**
         * What the prefix does to the SCOPE. Loose by default — of the two ways to be wrong,
         * omitting a project's own unprefixed legacy tables is the worse one, and the noise loose
         * can produce is visible and filterable while a silent omission is neither.
         */
        public PrefixScope $prefixScope = PrefixScope::Loose,
        /**
         * Whether objects OWNED by a database extension are included. Off by default, and that
         * default is the single largest false-positive saver on PostgreSQL: `postgis` alone
         * installs dozens of tables that are not the user's and that no user rule should judge.
         */
        public bool $includeExtensionObjects = false,
        /**
         * Whether each partition is reported as its own object. Off by default: a partitioned
         * table is ONE object to a rule, and reporting it as n multiplies every finding by the
         * partition count — which makes the first audit of a real database unreadable, and the
         * second one unrun.
         */
        public bool $reportPartitionsIndividually = false,
        /**
         * Extensions whose objects ARE this project's business, named one by one.
         *
         * Per-extension rather than a single switch, because the two cases are not the same size: a
         * project that manages its own `citext` domains should not have to take PostGIS's hundred
         * tables with it to say so.
         *
         * @var list<string>
         */
        public array $allowedExtensions = [],
    ) {}

    /**
     * The request a project's configuration asks for, with the caller supplying only the scope.
     *
     * The settings are read HERE rather than at each call site, because a config key whose value
     * nothing reads is a setting that documents a behavior the package does not have.
     *
     * `$tablePrefix` is nullable rather than defaulted to `''` for the same reason the caller's
     * schemas win: `''` is a real answer ("this project has no prefix"), so it has to be
     * distinguishable from "the caller did not say", which falls through to the configuration.
     *
     * `$schemas` overrides the configured scope rather than adding to it: a caller that names
     * schemas (a `--schema` option, a test) is making a narrower statement about THIS run, and
     * merging the two would produce a scope neither of them asked for.
     *
     * @param  list<string>  $schemas
     * @param  list<SchemaObjectType>  $types
     */
    public static function fromConfig(
        Repository $config,
        array $schemas = [],
        array $types = [],
        ?string $tablePrefix = null,
        ?bool $reportPartitionsIndividually = null,
        ?string $connection = null,
    ): self {
        $scope = $config->get('sqlens.catalog.prefix_scope');
        $names = self::stringsIn($config->get('sqlens.catalog.extensions.allow', []));

        return new self(
            schemas: $schemas === [] ? self::stringsIn($config->get('sqlens.catalog.schemas', [])) : $schemas,
            types: $types,
            tablePrefix: $tablePrefix ?? self::configuredPrefix($config, $connection),
            prefixScope: (is_string($scope) ? PrefixScope::tryFrom($scope) : null) ?? PrefixScope::Loose,
            includeExtensionObjects: (bool) $config->get('sqlens.catalog.include_extension_objects', false),
            reportPartitionsIndividually: $reportPartitionsIndividually
                ?? $config->get('sqlens.catalog.report_partitions_individually') === true,
            allowedExtensions: $names,
        );
    }

    /**
     * The prefix in force: SQLens's override, else the connection's own Laravel setting.
     *
     * Read from `database.connections.*.prefix` rather than assumed, because that is where every
     * ordinary Laravel project states it — and an audit that assumed no prefix on a project that has
     * one would report on a schema whose every table name the developer does not recognize.
     *
     * The override exists for the setups where the config file does NOT carry the value the app
     * uses: a prefix set at runtime, per tenant. `null` is therefore the ordinary "not overridden",
     * distinct from an override of `''` that somebody deliberately wrote.
     */
    private static function configuredPrefix(Repository $config, ?string $connection): string
    {
        $override = $config->get('sqlens.catalog.table_prefix');

        if (is_string($override)) {
            return $override;
        }

        $laravel = $connection === null ? null : $config->get('database.connections.'.$connection.'.prefix');

        return is_string($laravel) ? $laravel : '';
    }

    /**
     * The usable strings in a configured list.
     *
     * Read as names, never coerced into them: a non-string or blank entry is a configuration error,
     * and `ConfigSchema` reports it under its own key. Casting one here would turn a stated mistake
     * into a scope or an allowance nobody wrote.
     *
     * @return list<string>
     */
    private static function stringsIn(mixed $value): array
    {
        $strings = [];

        foreach (is_array($value) ? $value : [] as $item) {
            if (is_string($item) && trim($item) !== '') {
                $strings[] = $item;
            }
        }

        return $strings;
    }

    /** Whether this request asks for the given object type — true for every type when none is named. */
    public function wants(SchemaObjectType $type): bool
    {
        return $this->types === [] || in_array($type, $this->types, true);
    }

    /** Whether the schema scope is the reader's own default rather than an explicit list. */
    public function usesDefaultSchemaScope(): bool
    {
        return $this->schemas === [];
    }
}
