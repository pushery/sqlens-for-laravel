<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A `host` line in `pg_hba.conf` that authenticates with `trust`.
 *
 * `trust` means the server asks for nothing. Anyone who can open a TCP connection to it and name a
 * role is that role — no password, no certificate, no challenge. On a network line that is not a weak
 * password policy; it is the absence of authentication, and every other control in the database is
 * downstream of it.
 *
 * ## Why the local case is a different rule
 *
 * Reaching a Unix-domain socket already means being on the host, and being on the host usually means
 * being able to read the data directory anyway. So `local … trust` is a real finding with a
 * genuinely smaller blast radius, and it is {@see HbaTrustLocalRule} at `medium` rather than a
 * conditional inside this one: severity is metadata on the RULE in this package, so two severities
 * mean two ids — each with its own documentation page and its own baseline entry.
 */
final class HbaTrustRule extends AbstractHbaRule
{
    public function id(): string
    {
        return 'SEC.AUTH.HBA_TRUST';
    }

    /**
     * `critical`, and this is the one place in the security family where that word is not an
     * escalation but a description: the line states that no credential is required.
     */
    public function severity(): Severity
    {
        return Severity::Critical;
    }

    /** @return list<RuleVerdict> */
    protected function judgeRule(SchemaObject $object): array
    {
        if ($object->getBool('is_network') !== true || $object->getString('auth_method') !== 'trust') {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s accepts network connections with auth method trust, which asks for no credential at all: '
            .'anyone who can reach this server over the network and name a role IS that role. Replace trust '
            .'with scram-sha-256 on this line, and narrow %s if it does not need to be that wide.',
            $object->qualifiedName,
            $this->scope($object),
        ))];
    }

    /**
     * How the line is addressed, as the finding cites it.
     *
     * The address is named rather than merely the line, because "narrow this line" is not actionable
     * without saying what it currently allows — and `all` is both the most common value and the one
     * worth reading twice.
     */
    private function scope(SchemaObject $object): string
    {
        $address = $object->getString('address');

        return $address === null ? 'its address range' : 'its address range ('.$address.')';
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'judges each line on its own, and `pg_hba.conf` is FIRST-MATCH-WINS: a line reported here may sit below one that already matches every connection it would have accepted, in which case nothing ever reaches it. Reading the file as an ordered decision table is a different question',
            'reads what the server has LOADED, not what is on disk — an edit made and not reloaded is invisible here, and so is one already written that has not taken effect yet',
            'says nothing about what stands in front of the server. A `trust` line on an address range that no network route reaches is not an open door, and neither the routing nor the firewall is visible from the catalog',
        ];
    }
}
