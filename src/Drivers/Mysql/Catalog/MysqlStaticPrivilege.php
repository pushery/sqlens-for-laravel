<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Catalog;

/**
 * One static MySQL privilege: the grant-table column that stores it, and its name in a `GRANT`.
 *
 * The two are different strings often enough that a reader guessing one from the other would be
 * wrong for a third of the vocabulary — `Show_db_priv` / `SHOW DATABASES`, `Repl_slave_priv` /
 * `REPLICATION SLAVE`, `Create_tmp_table_priv` / `CREATE TEMPORARY TABLES`. Both are recorded.
 */
final readonly class MysqlStaticPrivilege
{
    /**
     * @param  list<string>  $scopes  the grant tables that carry this column
     * @param  string|null  $liftedTo  the grant field this column becomes instead of a privilege, or
     *                                 null when it is read as an ordinary one. `Grant_priv` is lifted
     *                                 to `grantable`, so the unpivot must not also emit it — one fact
     *                                 reported twice is the double report the catalog refuses.
     */
    public function __construct(
        public string $column,
        public string $privilege,
        public array $scopes,
        public ?string $liftedTo,
    ) {}

    public function appliesTo(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
