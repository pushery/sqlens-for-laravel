<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A `pg_hba.conf` line whose auth method is `password` — the password crosses the wire in the clear.
 *
 * PostgreSQL's `password` method is not a weaker hash; it is no hash at all. The client sends the
 * password as typed, and anything between client and server that can read the connection reads the
 * credential itself. Without TLS that is every hop on the path.
 *
 * ## Why this is not the same finding as `md5`
 *
 * {@see HbaMd5Rule} is about an obsolete CHALLENGE: the password is never sent, but the exchange can
 * be replayed and the stored digest is weak. This one is about no challenge existing. Merging them
 * would produce a finding that is true of neither, which is why the ticket that specified this family
 * insisted on separate ids.
 *
 * ## What this rule deliberately does not claim
 *
 * Whether the connection is encrypted. `hostssl` requires TLS and `hostnossl` forbids it, but a plain
 * `host` line permits either and the answer lies in the server's `ssl` setting rather than in this
 * line. That setting is read by a rule of its own, so this finding names the encryption question and
 * points at it instead of guessing — a `critical` asserted on an unread setting would be a severity
 * derived from an assumption.
 */
final class HbaCleartextRule extends AbstractHbaRule
{
    public function id(): string
    {
        return 'SEC.AUTH.HBA_CLEARTEXT';
    }

    /**
     * `high` on its own terms, and it stays `high` rather than escalating when TLS looks absent —
     * severity is metadata on the rule here, and an escalation that depended on a second reading
     * would be a severity that changes with what this run happened to be allowed to see.
     */
    public function severity(): Severity
    {
        return Severity::High;
    }

    /** @return list<RuleVerdict> */
    protected function judgeRule(SchemaObject $object): array
    {
        if ($object->getString('auth_method') !== 'password') {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s uses auth method password, which sends the password over the connection in the clear — '
            .'not hashed, not challenged. %s Change the method to scram-sha-256; every supported client '
            .'library speaks it, and it never puts the password on the wire.',
            $object->qualifiedName,
            $this->transportNote($object),
        ))];
    }

    /**
     * What the LINE itself says about encryption, and nothing more.
     *
     * Three honest answers rather than a guess: `hostnossl` forbids TLS outright, `hostssl` requires
     * it, and everything else leaves the question to the server's `ssl` setting — which this rule has
     * not read.
     */
    private function transportNote(SchemaObject $object): string
    {
        return match ($object->getString('type')) {
            'hostnossl' => 'This line is hostnossl, so the connection it governs is never encrypted and the '
                .'password is readable by anything on the path.',
            'hostssl' => 'This line is hostssl, so TLS protects the password in transit — which makes this a '
                .'weak method rather than an exposed credential.',
            'local' => 'This line is local, so the password crosses a Unix socket rather than the network.',
            default => 'Whether TLS protects it is decided by the server\'s ssl setting rather than by this '
                .'line, and this check does not read that setting — see SEC.AUTH.HBA_OPEN_CIDR for how wide '
                .'the exposure is.',
        };
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
            'judges the auth METHOD. Whether the password actually crosses the wire in the clear also depends on the line type and on the server\'s TLS being both enabled and required — three facts, of which this rule reads one',
        ];
    }
}
