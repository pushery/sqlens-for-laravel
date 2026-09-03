<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * Strips connection credentials out of text before it becomes user-visible — the
 * one discipline that keeps a database error message from carrying a host, a user,
 * or a password into a finding.
 *
 * A driver error that surfaces during a real shadow run is mostly a SQLSTATE and a
 * message about the schema, but a CONNECTION-level failure can embed the very
 * details that must never appear in output ("password authentication failed for
 * user …", a `host=… password=…` DSN, a `scheme://user:pass@host` URL). This
 * redacts those shapes rather than trusting that a particular error never carries
 * them — the same rule the later agent/MCP surface will need, defined once.
 *
 * It is a pure function: same text in, same redacted text out, so what it removes
 * is testable directly. It is conservative in what it touches — key/value
 * credential pairs, an auth-failure user, and URL userinfo — so a normal
 * schema-error message passes through unchanged.
 */
final class CredentialRedactor
{
    private const string REDACTED = '<redacted>';

    public function redact(string $text): string
    {
        // host=… port=… user=… password=… dbname=… — a libpq/DSN key/value pair.
        $text = preg_replace(
            '/\b(password|passwd|pwd|pgpassword|host|hostaddr|port|user|username|dbname|dsn)\s*=\s*[^\s;,)"\']+/i',
            '$1='.self::REDACTED,
            $text,
        ) ?? $text;

        // scheme://user:pass@host — credentials embedded in a connection URL.
        $text = preg_replace(
            '#([a-z][a-z0-9+.\-]*://)[^:@/\s]+:[^@/\s]+@#i',
            '$1'.self::REDACTED.'@',
            $text,
        ) ?? $text;

        // `connection to server at "10.0.0.4", port 5432 failed` — the standard libpq preamble on
        // EVERY PostgreSQL connection error since 12, and the reason this class was a no-op there:
        // it carries the host and port as PROSE, not as `host=`/`port=`, so every key/value pattern
        // above walks straight past them. Measured against a real server, not reconstructed.
        $text = preg_replace(
            '/\bconnection to server at\s+"[^"]*"(\s*\([^)]*\))?(\s*,\s*port\s+\d+)?/i',
            'connection to server at "'.self::REDACTED.'", port '.self::REDACTED,
            $text,
        ) ?? $text;

        // The Unix-socket form of the same preamble. The path names the directory the server runs
        // in, which on a shared host is as much of an address as a hostname.
        $text = preg_replace(
            '/\bconnection to server on socket\s+"[^"]*"/i',
            'connection to server on socket "'.self::REDACTED.'"',
            $text,
        ) ?? $text;

        // The principal, in every shape the two engines name it:
        //
        //   PostgreSQL   FATAL:  role "deploy" does not exist
        //   PostgreSQL   FATAL:  password authentication failed for user "deploy"
        //   MySQL        Access denied for user 'deploy'@'10.0.0.4' (using password: YES)
        //
        // The MySQL `@'host'` half is part of the same match rather than a separate pattern,
        // because redacting the user and leaving the host is how this used to "pass" while still
        // printing an address.
        //
        // Anchored on `role`/`user` and nothing else. A driver error also quotes schema objects —
        // `relation "users" does not exist`, `column "email"` — and those are the whole content of
        // a useful finding. A pattern that redacted any quoted identifier would have removed the
        // one thing the reader needs.
        $text = preg_replace(
            '/\b(role|user)\s+(["\'`])[^"\'`]*\2(\s*@\s*(["\'`])[^"\'`]*\4)?/i',
            '$1 "'.self::REDACTED.'"',
            $text,
        ) ?? $text;

        // `database "analytics_prod" does not exist` — the database name completes the coordinates
        // the three patterns above take apart, and a production database name is frequently the
        // customer's name.
        $text = preg_replace(
            '/\bdatabase\s+(["\'`])[^"\'`]*\1/i',
            'database "'.self::REDACTED.'"',
            $text,
        ) ?? $text;

        // LARAVEL'S OWN SUFFIX, and the most reliable leak of the lot.
        //
        // `QueryException::formatMessage()` appends
        // ` (Connection: pgsql, Host: 10.0.0.4, Port: 5432, Database: app, SQL: select 1)`
        // to EVERY query exception, on both engines, whatever the driver said. So even a message
        // that carried nothing sensitive of its own arrives wearing the connection's coordinates —
        // and when the connection configures a read-replica LIST, `Host:` is every one of them,
        // joined with commas (framework source, `formatConnectionDetails()`).
        //
        // The value therefore runs up to the NEXT key rather than to the next comma; stopping at
        // the comma would redact the first replica and print the rest. `Connection:` is left alone
        // on purpose — it is the name of a config entry, not an address, and it is the one part of
        // this suffix a reader needs to find the connection they misconfigured.
        return preg_replace(
            '/\b(Host|Port|Database|Username|Password):\s*(?:(?!,\s*(?:Host|Port|Database|Username|Password|SQL):)[^)])*/i',
            '$1: '.self::REDACTED,
            $text,
        ) ?? $text;
    }
}
