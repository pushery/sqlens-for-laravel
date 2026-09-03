<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * How an account's password is stored — the fact behind the deprecation rules on both engines.
 *
 * It is an enum rather than the raw hash prefix because the hash itself must never leave the reader
 * (the redaction sits at the reader, not at the reporter), and because both engines encode the same
 * three-way answer in incompatible spellings: PostgreSQL prefixes `md5…` / `SCRAM-SHA-256$…`, MySQL
 * names a plugin (`mysql_native_password` / `caching_sha2_password`).
 *
 * Measured on PostgreSQL 18: this fact
 * lives in `pg_authid`, which refuses `42501` to every role class we are willing to ask for — so
 * {@see self::Withheld} is the ORDINARY answer on a managed database rather than an edge case. That
 * is why it is a named case and not a null.
 */
enum PasswordHashType: string
{
    /** PostgreSQL `SCRAM-SHA-256$…`, MySQL `caching_sha2_password` / `sha256_password`. */
    case Scram = 'scram';

    /**
     * PostgreSQL `md5…`, MySQL `mysql_native_password`.
     *
     * Deprecated on both engines: PG 18 warns on creation and will remove support, and MySQL 8.4 no
     * longer enables the plugin by default. A rule about it therefore also has to handle "the plugin
     * is not even loadable", which is a different statement from "no account uses it".
     */
    case Md5 = 'md5';

    /** No password at all — PG `rolpassword IS NULL`, MySQL an empty `authentication_string`. */
    case None = 'none';

    /**
     * An external authenticator holds the credential: PG `ldap`/`gss`/`cert` via HBA, MySQL an
     * `auth_socket`/PAM/LDAP plugin.
     *
     * Not a weakness and not a gap — the credential is genuinely elsewhere, so a rule about hash
     * strength has nothing to judge and must not report the absence as a finding.
     */
    case External = 'external';

    /**
     * The catalog that holds it was not readable.
     *
     * A named case rather than a null, because null invites `?? self::None` and "we could not look"
     * would silently become "there is no password" — the one substitution that turns a locked door
     * into an open one in a report.
     */
    case Withheld = 'withheld';

    /**
     * The MySQL answer, from the plugin name and whether a credential is stored.
     *
     * On the type rather than in the reader, and that is not tidiness: three of the four outcomes
     * cannot be produced on a live MySQL 8.4 — the server will not create an account on a plugin it no
     * longer loads, and an external authenticator needs one installed. A mapping that only a server
     * could exercise would be a mapping nobody has ever seen make its rarer decisions.
     */
    public static function forMysqlPlugin(string $plugin, bool $hasCredential): self
    {
        $plugin = strtolower($plugin);
        $native = in_array($plugin, ['caching_sha2_password', 'sha256_password', 'mysql_native_password'], true);

        // An external authenticator holds the credential elsewhere, so "no digest stored" is correct
        // there and says nothing about strength. Under a native plugin the same emptiness means an
        // account with no password at all, which is the opposite kind of news.
        return match (true) {
            ! $native => self::External,
            ! $hasCredential => self::None,
            $plugin === 'mysql_native_password' => self::Md5,
            default => self::Scram,
        };
    }

    /** Whether this type is one the engines are retiring, and rules should flag. */
    public function isDeprecated(): bool
    {
        return $this === self::Md5;
    }

    /** Whether a rule may conclude anything at all from this value. */
    public function isKnown(): bool
    {
        return $this !== self::Withheld;
    }
}
