<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A `pg_hba.conf` line whose auth method is `md5`.
 *
 * The stored verifier is `md5(password || rolname)` — an unsalted-in-any-useful-sense MD5, since the
 * role name is public. Anybody who obtains the digest can compute passwords against it offline at
 * enormous speed, and the digest itself is a password equivalent: the protocol accepts a client that
 * knows only the digest. `scram-sha-256` fixes both, and PostgreSQL has shipped it since version 10.
 *
 * ## Two halves of one problem, two rules
 *
 * This rule is about the METHOD a connection negotiates. What a role has STORED is a separate fact,
 * read from `pg_authid` and reported by the password-hash rule — and the two do not have to agree: a
 * role can hold a SCRAM verifier while an HBA line still offers `md5`, in which case the server
 * negotiates SCRAM and the line is a latent hazard rather than an active one. Reporting one finding
 * for both would be wrong about whichever half did not apply, so they stay separate and each names
 * the other.
 */
final class HbaMd5Rule extends AbstractHbaRule
{
    public function id(): string
    {
        return 'SEC.AUTH.HBA_MD5';
    }

    /**
     * `high`: the failure mode is a credential recoverable offline, or reusable without ever being
     * recovered. Not `critical`, because a challenge does still take place — the distinction from
     * {@see HbaCleartextRule}, where none does.
     */
    public function severity(): Severity
    {
        return Severity::High;
    }

    /** @return list<RuleVerdict> */
    protected function judgeRule(SchemaObject $object): array
    {
        if ($object->getString('auth_method') !== 'md5') {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s negotiates md5 authentication. Its verifier is md5 over the password and the role name, so '
            .'the role name is the only salt and a captured digest is both crackable offline and usable as '
            .'the password itself. Set password_encryption to scram-sha-256, have each role set its '
            .'password again so a SCRAM verifier is stored, then change this line to scram-sha-256 — in '
            .'that order, or the roles will be unable to authenticate. What each role currently has stored '
            .'is a separate finding.',
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
            'the method a line names and the method a connection ends up using are not always the same: a role whose stored verifier is SCRAM does not authenticate with md5 regardless of what this line says, so a project mid-migration may be safer than this reads',
        ];
    }
}
