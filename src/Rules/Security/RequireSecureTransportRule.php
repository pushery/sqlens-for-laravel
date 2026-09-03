<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The server accepts unencrypted connections — it does not merely offer encryption, it permits its
 * absence.
 *
 * The distinction is the finding. MySQL 8 negotiates TLS by default and most clients take it, so a
 * server with `require_secure_transport = OFF` usually looks encrypted from the inside: every
 * connection somebody checks is one that happened to negotiate it. What the setting decides is
 * whether a connection that does NOT is refused — and a client that omits it, or one whose TLS setup
 * silently failed, connects exactly as before, in the clear, with no error anywhere.
 *
 * So this is not "encryption is off". It is "nothing enforces that it is on", which is the state in
 * which a misconfigured client can go unnoticed for years.
 *
 * ## Why `medium` rather than higher
 *
 * On a server reachable only over a private network the exposure is bounded by that network, and
 * plenty of correct deployments rely on exactly that. What the setting removes is a guarantee, not a
 * defense — and a finding that treated a private-network deployment as critical would be switched
 * off before it was read.
 *
 * ## What this cannot see
 *
 * Whether a managed provider enforces transport OUTSIDE the server's own configuration. Several do,
 * at the proxy, and the server variable then reads `OFF` on a connection that cannot be made in the
 * clear at all. The finding says the SERVER does not require it, and says that is what it means.
 */
final class RequireSecureTransportRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.REQUIRE_SECURE_TRANSPORT';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    #[Override]
    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'require_secure_transport';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        $value = strtoupper(trim($serverValue));

        if ($value === 'ON' || $value === '1') {
            return null;
        }

        return sprintf(
            'require_secure_transport is %s, so this server ACCEPTS unencrypted connections. That is '
            .'not the same as "encryption is off": MySQL 8 negotiates TLS by default and most clients '
            .'take it, so the connections anybody checks are usually encrypted. What this setting '
            .'decides is whether one that is NOT gets refused — and a client that omits TLS, or whose '
            .'TLS setup silently failed, connects exactly as before, in the clear, with nothing '
            .'raised anywhere. The state this reports is "nothing enforces it", which is how a '
            .'misconfigured client goes unnoticed for years. Note the limit: several managed '
            .'providers enforce transport at a proxy OUTSIDE the server configuration, and this '
            .'variable reads OFF on such a server even though no connection can be made in the '
            .'clear. This says the SERVER does not require it. %s',
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
            'says the server ACCEPTS unencrypted connections, not that anything makes one. A deployment where every client is configured to require TLS is not transmitting in the clear today — it is one misconfigured client away from doing so, which is the distinction this rule is about',
        ];
    }
}
