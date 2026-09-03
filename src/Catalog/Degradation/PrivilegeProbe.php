<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Degradation;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Contracts\CatalogPrivileges;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Throwable;

/**
 * Asks what this role may read BEFORE reading it, so an under-privileged audit says so.
 *
 * ## The failure this exists to catch is silent on both engines, in different ways
 *
 * Measured on a real PostgreSQL 18 and MySQL 8.4, with a role holding nothing but `USAGE`:
 *
 * - **MySQL filters `information_schema` by privilege, without a word.** The same query that
 *   returns a database's tables to `root` returns ZERO ROWS to a role with no grants. No error, no
 *   warning — a clean, empty, complete-looking audit of a database the reader could not see. This is
 *   the single most dangerous shape in this package's problem space, and nothing but a probe finds
 *   it: the reading itself succeeded.
 * - **PostgreSQL mostly answers, and hides the rest a row at a time.** `pg_class` and `pg_index` are
 *   world-readable, so the core reading works even on a managed instance — but `pg_settings` simply
 *   OMITS a superuser-only setting rather than refusing it, and `pg_hba_file_rules` refuses outright
 *   with `42501`. One silent, one loud, from the same server.
 *
 * ## Read-only, lock-free, and it never throws
 *
 * A probe that raised on a database it was only meant to look at would be worse than the gap it
 * reports. Every area's question is a plain `SELECT`; a question that itself fails becomes a skip
 * through the same translator the reading uses, so "the probe could not tell" is a stated answer
 * rather than a crash.
 */
final readonly class PrivilegeProbe
{
    public function __construct(private CatalogPrivileges $privileges) {}

    /**
     * Every area this role cannot read, as named skips.
     *
     * @param  list<string>  $schemas
     * @return list<CatalogSkip>
     */
    #[RawSql(reason: 'runs the driver own catalog SQL to ask what this role may read; the subject is the catalog, which is not a model')]
    public function run(Connection $reader, array $schemas): array
    {
        $skips = [];

        foreach ($this->privileges->areas($schemas) as $area) {
            try {
                $rows = $reader->select($area->sql, $area->bindings);
            } catch (Throwable $error) {
                // The probe failing is itself a gap, not an outage: the reading may still work, and
                // what is lost is only the ability to say in advance that it would not.
                $skips[] = DatabaseErrorTranslator::skipFor(SchemaObjectType::Table, $area->name, $error);

                continue;
            }

            if ($this->answeredYes($rows)) {
                continue;
            }

            $skips[] = CatalogSkip::for(
                SchemaObjectType::Table,
                $area->name,
                SkipReason::InsufficientPrivilege,
                $area->consequence,
            );
        }

        return $skips;
    }

    /**
     * Whether the area's question came back affirmative.
     *
     * An EMPTY result counts as no, and that is the load-bearing half: MySQL's answer to "how many
     * of this database's tables can you see" is a row holding `0`, while PostgreSQL's answer to a
     * question about a setting it will not show is no row at all. Both mean the same thing, and a
     * probe that only understood one of them would pass on the engine it did not.
     *
     * @param  array<int|string, mixed>  $rows
     */
    private function answeredYes(array $rows): bool
    {
        $first = array_values($rows)[0] ?? null;

        if (! is_object($first)) {
            return false;
        }

        $values = array_values((array) $first);

        return (bool) ($values[0] ?? false);
    }
}
