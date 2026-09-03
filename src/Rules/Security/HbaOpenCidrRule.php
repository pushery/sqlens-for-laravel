<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A network line in `pg_hba.conf` that accepts connections from the entire address space.
 *
 * `0.0.0.0/0` — or `all`, or `::/0` — is the door that makes every other weakness reachable. On its
 * own it is not a breach: a line that is open but demands `scram-sha-256` still demands a password.
 * It is the multiplier, which is why it is reported separately from the method rules rather than
 * folded into them.
 *
 * ## The four spellings are one fact, and that is why the check is not a regex
 *
 * `pg_hba.conf` writes the same statement as `all`, as `0.0.0.0/0`, as `0.0.0.0 0.0.0.0`, and as
 * `::/0` — and `pg_hba_file_rules` splits some of those across the address and netmask columns. A
 * rule matching on text would answer differently for four spellings of one thing, so the question is
 * asked of the canonicalized object instead. `samehost` and `samenet` are not open: they resolve to
 * the server's own addresses.
 *
 * ## What it says when the same line also has a weak method
 *
 * It names it and points at the rule that reports it, rather than raising its own severity. The other
 * rule has already produced a finding about that line at ITS severity — `SEC.AUTH.HBA_TRUST` is
 * `critical` — so escalating here would put two findings of the same weight on one line and leave a
 * reader to work out that they are the same problem.
 */
final class HbaOpenCidrRule extends AbstractHbaRule
{
    public function id(): string
    {
        return 'SEC.AUTH.HBA_OPEN_CIDR';
    }

    /**
     * `high`: the line is what makes a credential guessable from anywhere rather than from a bounded
     * network. It is not `critical` on its own, because a strong method still stands behind it.
     */
    public function severity(): Severity
    {
        return Severity::High;
    }

    /** @return list<RuleVerdict> */
    protected function judgeRule(SchemaObject $object): array
    {
        if ($object->getBool('is_network') !== true || $object->getBool('open_cidr') !== true) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s accepts connections from the entire address space (%s), so this server is reachable from '
            .'any host that can route to it.%s Narrow the line to the networks that actually connect — the '
            .'application subnet, the office range — and let everything else be refused before a password '
            .'is ever guessed at.',
            $object->qualifiedName,
            $object->getString('address') ?? 'all',
            $this->methodNote($object),
        ))];
    }

    /**
     * The sentence that turns "wide" into "wide open", when the method on the same line is one of the
     * two that ask for little or nothing.
     */
    private function methodNote(SchemaObject $object): string
    {
        return match ($object->getString('auth_method')) {
            'trust' => ' The method on this line is trust, so it asks for no credential either — see '
                .'SEC.AUTH.HBA_TRUST, which is the finding to fix first.',
            'password' => ' The method on this line is password, so the credential also crosses the wire in '
                .'the clear — see SEC.AUTH.HBA_CLEARTEXT.',
            'md5' => ' The method on this line is md5, whose verifier is recoverable offline — see '
                .'SEC.AUTH.HBA_MD5.',
            default => '',
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
            'an address range is not reachability. `0.0.0.0/0` behind a private subnet accepts nothing from outside it, and where the server actually sits is not something a catalog read can answer',
        ];
    }
}
