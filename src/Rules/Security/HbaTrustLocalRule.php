<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A `local` line in `pg_hba.conf` that authenticates with `trust`.
 *
 * The Unix-domain-socket half of {@see HbaTrustRule}, and a separate rule because it is a genuinely
 * different statement about risk. Reaching the socket already requires being on the host, and anybody
 * on the host with the server's OS account can generally read the data directory regardless. So the
 * line does not open the database to the network; it removes the last separation between OS access
 * and database access — which still matters, because the two are not the same set of people on a
 * machine that runs anything beside PostgreSQL.
 *
 * ## Why not one rule with a conditional severity
 *
 * Severity is metadata on the RULE here, so a conditional would give one id two meanings — and with
 * it one documentation page, one baseline entry and one suppression covering two different decisions.
 * `SEC.RLS.NOT_FORCED` and `SEC.RLS.OWNER_UNRESTRICTED` split for exactly this reason.
 */
final class HbaTrustLocalRule extends AbstractHbaRule
{
    public function id(): string
    {
        return 'SEC.AUTH.HBA_TRUST_LOCAL';
    }

    /**
     * `medium`: it is a real removal of a control, and its blast radius is bounded by who can already
     * open a socket on the host. Rating it `critical` alongside the network case would make the two
     * indistinguishable in a report, and the network case is the one that has to be read first.
     */
    public function severity(): Severity
    {
        return Severity::Medium;
    }

    /** @return list<RuleVerdict> */
    protected function judgeRule(SchemaObject $object): array
    {
        if ($object->getString('type') !== 'local' || $object->getString('auth_method') !== 'trust') {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s authenticates Unix-socket connections with trust, so any process on this host that can '
            .'open the socket connects as any role it names — including roles it was never granted. That '
            .'is narrower than the same setting on a network line (see SEC.AUTH.HBA_TRUST), and it still '
            .'means OS access and database access are the same thing here. Use peer for the operator '
            .'account and scram-sha-256 for the application.',
            $object->qualifiedName,
        ))];
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
            'a `local` line is the unix socket, so the exposure is exactly the set of accounts with shell access to the database host — which is an operations fact this rule cannot read, and the reason this case is graded apart from its `host` sibling',
        ];
    }
}
