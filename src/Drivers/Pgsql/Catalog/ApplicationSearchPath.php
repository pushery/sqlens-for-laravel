<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Catalog;

/**
 * The application's search path, recorded before a reading pins its own.
 *
 * A reading session runs with nothing but `pg_catalog` on its path, so that no function or operator
 * it names can resolve in a schema somebody else may write to. The names a MIGRATION writes still
 * resolve on the path the application connects with: `Schema::table('orders', …)` means the
 * `orders` an unqualified name finds there, and so does a bare name in a grant, a lock or a
 * statistics lookup. Asked of the pinned session, `pg_table_is_visible()`, `to_regclass()` and
 * `current_schema()` would answer about `pg_catalog` alone and find none of them.
 *
 * So the path is recorded once, inside the read transaction and before the pin, into two settings
 * that end with the transaction, and every answer about a bare name reads it from there.
 */
final readonly class ApplicationSearchPath
{
    /** The path as the server searches it, implicit schemas included, in their order. */
    public const string EFFECTIVE = 'sqlens.search_path';

    /** The path as configured, without the implicit schemas: what `current_schemas(false)` answers. */
    public const string EXPLICIT = 'sqlens.explicit_search_path';

    /**
     * The statement that records both, local to the transaction it runs in.
     *
     * @return literal-string
     */
    public static function recordStatement(): string
    {
        return "select pg_catalog.set_config('".self::EFFECTIVE."', pg_catalog.current_schemas(true)::text, true),"
            ." pg_catalog.set_config('".self::EXPLICIT."', pg_catalog.current_schemas(false)::text, true)";
    }

    /**
     * Whether the relation aliased `$class` is the one an unqualified name finds on the application's
     * path, which is what `pg_table_is_visible()` answers for the session's own path: the first
     * schema on the path holding a relation of that name.
     *
     * Every fragment here is a literal, and typed so: the statements it lands in are checked for a
     * runtime value assembled into their text, and none reaches them through this class.
     *
     * @param  literal-string  $class
     * @return literal-string
     */
    public static function visible(string $class): string
    {
        return $class.'.relnamespace = ('
            .'select c2.relnamespace from pg_catalog.pg_class c2'
            .' join pg_catalog.pg_namespace n2 on n2.oid = c2.relnamespace'
            .' where c2.relname = '.$class.'.relname'
            .' and n2.nspname = any('.self::effective().')'
            .' order by pg_catalog.array_position('.self::effective().', n2.nspname)'
            .' limit 1)';
    }

    /**
     * `pg_catalog.to_regclass()` over a name as a migration writes it. A qualified name is looked up
     * as it stands; a bare one is qualified first with the schema the application's path finds it
     * in, and stays bare, and so unresolved, when no schema on that path holds it.
     *
     * Takes the three bindings {@see self::regclassBindings()} returns.
     *
     * @return literal-string
     */
    public static function regclass(): string
    {
        return 'pg_catalog.to_regclass(coalesce(('
            .'select pg_catalog.format(\'%I.%I\', n2.nspname, c2.relname) from pg_catalog.pg_class c2'
            .' join pg_catalog.pg_namespace n2 on n2.oid = c2.relnamespace'
            .' where pg_catalog.strpos(?, \'.\') = 0 and c2.relname = ?'
            .' and n2.nspname = any('.self::effective().')'
            .' order by pg_catalog.array_position('.self::effective().', n2.nspname)'
            .' limit 1), ?))';
    }

    /** @return list<string> */
    public static function regclassBindings(string $name): array
    {
        return [$name, $name, $name];
    }

    /**
     * The schemas the application's path names, without the implicit ones, as a `name[]`.
     *
     * @return literal-string
     */
    public static function explicit(): string
    {
        return 'pg_catalog.current_setting(\''.self::EXPLICIT.'\')::name[]';
    }

    /**
     * What `current_schema()` answers for the application: the first schema on its path that exists.
     *
     * @return literal-string
     */
    public static function currentSchema(): string
    {
        return '('.self::explicit().')[1]';
    }

    /** @return literal-string */
    private static function effective(): string
    {
        return 'pg_catalog.current_setting(\''.self::EFFECTIVE.'\')::name[]';
    }
}
