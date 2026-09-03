<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * PostgreSQL is not offering TLS at all — no connection to this server can be encrypted.
 *
 * Stronger than the MySQL finding it sits beside. {@see RequireSecureTransportRule} reports a server
 * that offers encryption and does not insist on it, so most connections there are in fact encrypted
 * and the finding is about a missing guarantee. `ssl = off` is the other thing entirely: the server
 * cannot negotiate TLS, so every connection is in the clear, including the ones somebody checks.
 *
 * There is nothing a client can do about it either. On MySQL a careful client can insist on its side;
 * here the capability is absent from the server, so insisting fails the connection rather than
 * securing it.
 *
 * ## Why `high` and not `critical`
 *
 * Plenty of correct deployments reach PostgreSQL over a unix socket or a private network the
 * database shares with nothing else, and for those the exposure is bounded by that network rather
 * than by this setting. `critical` is reserved here for findings that need nothing else to be true —
 * this one needs somebody to be able to reach the wire.
 *
 * The combination that IS critical — TLS off AND an authentication rule accepting an open CIDR — is
 * a separate escalation, because it needs a fact from a different reader and must say so when that
 * reader could not answer.
 */
final class TlsDisabledRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.TLS_DISABLED';
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
        return 'ssl';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // PostgreSQL reports a boolean setting as `on`/`off`, but the same value arrives as `true`,
        // `1` or `yes` from a configuration file, and flagging a spelling would be a false positive
        // about `postgresql.conf` rather than about the server.
        $value = strtolower(trim($serverValue));

        if (in_array($value, ['on', 'true', '1', 'yes'], true)) {
            return null;
        }

        return sprintf(
            'ssl is %s, so this server does not offer TLS at all and every connection to it runs in '
            .'the clear — including the ones somebody checks. That is a stronger statement than an '
            .'unenforced transport: there, encryption is available and merely not insisted upon, so '
            .'most connections are in fact encrypted. Here the capability is absent, and a careful '
            .'client cannot make up for it — insisting on TLS fails the connection rather than '
            .'securing it. Reported below critical because a deployment reached over a unix socket '
            .'or a private network the database shares with nothing else is bounded by that network '
            .'rather than by this setting; what makes it worse is an authentication rule that accepts '
            .'an open address range, which is a separate finding. %s',
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
            // "none of that topology is visible" was too strong in one direction and too weak in the
            // other: the pooler reading establishes whether a pooler is in the path, and no reading
            // reaches what any proxy does with TLS. Both halves are stated so a reader knows which
            // question was answered.
            'describes the SERVER\'s offer. A connection reaching it through a proxy or a service mesh that terminates TLS elsewhere may still be encrypted on the wire that matters; whether a pooler is in the path is established and reported beside this finding, but what any proxy negotiates with a client is not visible from the catalog',
        ];
    }
}
