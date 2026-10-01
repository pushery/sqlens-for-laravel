<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use PDO;

/**
 * A read handle for pretend mode that quotes a value without a server.
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

    public function __construct(private readonly string $driver) {}

    public function quote(string $string, int $type = PDO::PARAM_STR): string
    {
        return match ($this->driver) {
            'mysql', 'mariadb' => "'".strtr($string, self::MYSQL_ESCAPES)."'",
            default => "'".str_replace("'", "''", $string)."'",
        };
    }
}
