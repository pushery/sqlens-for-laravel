<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The server stores every NEW password with a hash PostgreSQL has deprecated.
 *
 * The only finding in the md5 family that reports a server which is CLEAN today. Its two neighbors
 * both need something to already be wrong: {@see DeprecatedPasswordHashRule} needs an account whose
 * stored verifier is md5, and {@see HbaMd5Rule} needs an authentication rule that negotiates md5 on
 * the wire. A server with `password_encryption = md5` and no md5 passwords yet passes both of them —
 * and produces a new md5 verifier for every `ALTER ROLE … PASSWORD` and every `\password` from now
 * on, silently, with nothing failing.
 *
 * So the three say three different sentences about three different times: what the accounts ARE,
 * what the wire NEGOTIATES, and what the next password WILL BE. Only the last one is preventable
 * before the fact, which is the whole reason this rule earns its place beside them.
 *
 * ## Why md5 in particular
 *
 * PostgreSQL's md5 verifier is salted with the ROLE NAME and nothing else. Two servers carrying a
 * role called `app` therefore produce the same digest for the same password, so a digest captured
 * anywhere is crackable offline AND replayable as the password itself against every other server
 * that role exists on. `scram-sha-256` has a per-password random salt and an iteration count, and it
 * never puts anything replayable on the wire.
 *
 * ## The honesty limit, and it is measured rather than assumed
 *
 * `password_encryption` has context `user` — measured on PostgreSQL 18.4, where a plain `SET` in an
 * ordinary session changes it. So the server's value is the DEFAULT new connections inherit, not an
 * enforcement: a session that sets it to md5 itself writes an md5 verifier however the server is
 * configured. Fixing this stops the server from producing them by default; it does not make them
 * impossible. The finding says so rather than letting a reader assume otherwise.
 *
 * The same measurement is why the base class reads `server_value` and never `value` — with that
 * `SET` in place `pg_settings` answers `setting = md5` beside `reset_val = scram-sha-256`, so a rule
 * reading the session's value would report the audit's own connection as the server's configuration.
 *
 * ## Why anything other than `scram-sha-256` is the finding
 *
 * Not a guess about unknown values: the parameter is an enum, and PostgreSQL 18 rejects a third one
 * outright — `SET password_encryption = 'argon2'` answers `invalid value … Available values: md5,
 * scram-sha-256`. So the closed comparison is exact on every version this entry covers, and a value
 * that is not `scram-sha-256` is md5 by elimination.
 */
final class PasswordEncryptionRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.PASSWORD_ENCRYPTION';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    #[Override]
    public function severity(): Severity
    {
        return Severity::High;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'password_encryption';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Case-insensitive, though the server canonicalizes: measured on 18.4, `SET
        // password_encryption = 'SCRAM-SHA-256'` reads back as the lower-case spelling. The folding
        // is therefore not load-bearing here — it costs nothing, and the failure it rules out is the
        // one worth ruling out, since a casing mismatch would report a correctly hardened server.
        if (strcasecmp(trim($serverValue), 'scram-sha-256') === 0) {
            return null;
        }

        return sprintf(
            'password_encryption is %s, so every password set on this server from now on is stored '
            .'with a hash PostgreSQL has deprecated — no error, no warning at the connection, and '
            .'nothing in a migration to notice. The md5 verifier is salted with the ROLE NAME and '
            .'nothing else, so two servers carrying a role of the same name produce the same digest '
            .'for the same password: one captured anywhere is crackable offline and replayable as '
            .'the password itself everywhere that role exists. Note what this does and does not say. '
            .'It is about the NEXT password, not the ones already stored — those are reported '
            .'separately, per account — and this parameter can be set by any session, so it is the '
            .'default new connections inherit rather than a rule they cannot break. %s',
            $serverValue,
            $this->remediation($expectation),
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the RUNNING value, not the file: a setting changed on disk and not yet reloaded is invisible here, and one changed only for this session would be read as the server\'s',
            'governs only passwords set FROM NOW ON. Every verifier already stored keeps the algorithm it was written with, so changing this setting fixes nothing retroactively — which is exactly why the finding matters before the next password is set rather than after',
            'cannot see which verifiers are already stored: that is the role-attribute rules\' question, and answering it here would report the same fact twice',
        ];
    }
}
