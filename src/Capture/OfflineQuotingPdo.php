<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use PDO;
use PDOException;

/**
 * A handle for pretend mode that quotes a value, and names a server version, without a server.
 *
 * In pretend mode Laravel writes each binding into the logged statement, and a string goes through
 * the read handle's `quote()`. The handle a capture connection would resolve is a live one, so
 * logging a single string value would open a connection. This handle is never connected: its
 * constructor does not call PDO's, `quote()` is the one method it answers, and any other PDO
 * method fails as uninitialized instead of reaching a server.
 *
 * It quotes the way the driver's own `PDO::quote()` does under the server's default mode, so a
 * logged statement is the same with or without a server. MySQL and MariaDB escape a backslash,
 * both quotes, NUL, the line breaks and Ctrl-Z with a backslash; every other driver doubles the
 * single quote.
 *
 * Given the version the run reasons about, it also answers `PDO::ATTR_SERVER_VERSION`. Laravel's
 * MySQL grammar asks the connection for it to declare a date, year or geometry column and to
 * rename a column, so a write handle that answers it lets those migrations compile as they would
 * against that server. Without a version the attribute fails like every other.
 *
 * As a write handle it also keeps a transaction. A migration that opens one, through
 * `DB::transaction()` or a library that wraps its statements in one, reaches the handle's
 * `beginTransaction()`, `commit()`, `rollBack()` and `inTransaction()`, and a nested one sends its
 * savepoint to `exec()`. Under pretend nothing runs, so the handle keeps whether a transaction is
 * open, as a server would, and answers a savepoint with no row. Any other statement handed to
 * `exec()` fails as uninitialized, because a live handle would run it.
 */
final class OfflineQuotingPdo extends PDO
{
    private const array MYSQL_ESCAPES = [
        '\\' => '\\\\',
        "\0" => '\\0',
        "\n" => '\\n',
        "\r" => '\\r',
        "'" => "\\'",
        '"' => '\\"',
        "\x1a" => '\\Z',
    ];

    private bool $transaction = false;

    public function __construct(private readonly string $driver, private readonly ?string $serverVersion = null) {}

    public function quote(string $string, int $type = PDO::PARAM_STR): string
    {
        return match ($this->driver) {
            'mysql', 'mariadb' => "'".strtr($string, self::MYSQL_ESCAPES)."'",
            default => "'".str_replace("'", "''", $string)."'",
        };
    }

    /**
     * @return mixed the attribute, of whatever type PDO keeps for it
     */
    public function getAttribute(int $attribute): mixed
    {
        if ($attribute === PDO::ATTR_SERVER_VERSION && $this->serverVersion !== null) {
            return $this->serverVersion;
        }

        return parent::getAttribute($attribute);
    }

    /**
     * Opens a transaction, which under pretend runs nothing, so the handle keeps only that one is open.
     *
     * @throws PDOException where one is open already, as a server answers
     */
    public function beginTransaction(): bool
    {
        if ($this->transaction) {
            throw new PDOException('There is already an active transaction');
        }

        $this->transaction = true;

        return true;
    }

    /**
     * Closes the open transaction.
     *
     * @throws PDOException where none is open, as a server answers
     */
    public function commit(): bool
    {
        return $this->closeTransaction();
    }

    /**
     * Closes the open transaction, which under pretend wrote nothing to undo.
     *
     * @throws PDOException where none is open, as a server answers
     */
    public function rollBack(): bool
    {
        return $this->closeTransaction();
    }

    public function inTransaction(): bool
    {
        return $this->transaction;
    }

    /**
     * Answers the savepoint of a nested transaction with no row, and fails every other statement as
     * uninitialized.
     *
     * Laravel opens, and rolls back to, the savepoint of a nested transaction through the handle itself
     * rather than through a logged statement. A statement of any other kind would run on a live
     * handle, so it is reported rather than passed over.
     */
    public function exec(string $statement): int|false
    {
        if (preg_match('/^\s*(?:SAVEPOINT|RELEASE\s+SAVEPOINT|ROLLBACK\s+TO\s+SAVEPOINT)\s/i', $statement) === 1) {
            return 0;
        }

        return parent::exec($statement);
    }

    /** @throws PDOException where no transaction is open */
    private function closeTransaction(): bool
    {
        if (! $this->transaction) {
            throw new PDOException('There is no active transaction');
        }

        $this->transaction = false;

        return true;
    }
}
