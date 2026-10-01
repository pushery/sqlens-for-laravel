<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Drivers\Pgsql\Catalog\ApplicationSearchPath;

/**
 * The tables some indexes belong to, as the catalog records them.
 *
 * A `DROP INDEX` names its index and nothing else, and the lock it takes is on the TABLE. A preflight
 * that asks which sessions or which vacuum stand in front of a statement has to know that table, and
 * only the catalog can say.
 */
final readonly class IndexTables
{
    /**
     * The tables of the given indexes, schema-qualified, sorted and without repeats.
     *
     * An index is matched two ways for the reason the activity reader gives: a migration writes a bare
     * name, and a bare name is compared with the indexes the application's search path would resolve,
     * never with a guessed schema. An index the catalog does not know yet, one the pending migration
     * creates before it drops it, has no table to lock now and is left out.
     *
     * @param  list<string>  $indexes
     * @return list<string>
     */
    #[RawSql(reason: 'resolves an index to its table through pg_index; the relation an index belongs to is a catalog fact with no other representation')]
    public static function of(ReaderSession $session, array $indexes): array
    {
        if ($indexes === []) {
            return [];
        }

        $placeholders = implode(', ', array_fill(0, count($indexes), '?'));
        $visible = ApplicationSearchPath::visible('i');

        $rows = $session->read(static fn (Connection $db): array => $db->select(
            <<<SQL
                select tn.nspname || '.' || t.relname as relation
                  from pg_catalog.pg_index x
                  join pg_catalog.pg_class i on i.oid = x.indexrelid
                  join pg_catalog.pg_namespace n on n.oid = i.relnamespace
                  join pg_catalog.pg_class t on t.oid = x.indrelid
                  join pg_catalog.pg_namespace tn on tn.oid = t.relnamespace
                 where n.nspname || '.' || i.relname in ({$placeholders})
                    or (i.relname in ({$placeholders}) and {$visible})
                 order by relation
                SQL,
            [...$indexes, ...$indexes],
        ));

        $tables = [];

        foreach ($rows as $row) {
            if (is_object($row) && property_exists($row, 'relation') && is_string($row->relation)) {
                $tables[] = $row->relation;
            }
        }

        return array_values(array_unique($tables));
    }
}
