<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An account holds every privilege the engine has on this object — the multiplier under every other
 * finding in this suite.
 *
 * It is not one problem among the others; it is the reason the others are worth reporting at all. An
 * account with `ALL PRIVILEGES` needs no privilege escalation, because there is nothing above it to
 * escalate to: an injection reaching it can read every row, change the schema, and — where the grant
 * is global — read and write files through the server. Every narrower finding describes a step
 * somebody would still have to take. This one describes the destination.
 *
 * ## Why the reader answers the question and this rule only reads the answer
 *
 * `GRANT ALL PRIVILEGES` leaves no trace of the word `ALL`. Both engines expand it immediately —
 * MySQL into one `Y` per column, PostgreSQL into one ACL entry per privilege — so recognizing it
 * afterwards means knowing what "every privilege" IS on that engine, for that kind of object. That
 * is engine vocabulary, and the core is kept free of it by an architecture test rather than by
 * habit. So each driver answers for itself, from a source that cannot go stale: PostgreSQL asks
 * `acldefault()`, which is the server stating its own complete set, and MySQL compares against the
 * grant-table columns its reading was generated from.
 *
 * ## What the finding does NOT say
 *
 * That the account is wrong. An administrative account, a replication account and a migration
 * account are all deliberately broad, and a rule treating every hit as a mistake would be switched
 * off in the week somebody ran it against a real server. The finding is the LIST of accounts for
 * which this ought to have been a decision — the value is in a name on it that nobody expected.
 *
 * And it reads privileges rather than behavior. A clean result here does not mean an application
 * cannot be injected; it means one specific consequence is off the table.
 */
final class AllPrivilegesGrantRule extends AbstractSchemaObjectSecurityRule implements DeclaresJudgedObjectTypes
{
    /**
     * Grants only. The grant reading is refusable on a managed database, which makes "no subject" an
     * ordinary state here — and one a report must not present as a check that ran.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Grant];
    }

    public function id(): string
    {
        return 'SEC.PRIV.GRANT_ALL';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Grant) {
            return [];
        }

        // A grant the ENGINE ships is not a decision anybody made. MySQL's own `mysql.session` holds
        // most of the administrative vocabulary out of the box, and reporting it would open the suite
        // with a finding on every server that nobody caused and nobody may revoke.
        if ($object->getBool('judgeable') !== true) {
            return [];
        }

        if ($object->getBool('all_privileges') !== true) {
            return [];
        }

        return [RuleVerdict::flag($this->message($object))];
    }

    private function message(SchemaObject $object): string
    {
        return sprintf(
            '%s holds EVERY privilege this engine has on the %s %s — the state a grant reaches when '
            .'it is written as ALL PRIVILEGES, whether or not those words were used. There is no '
            .'privilege escalation left to perform against this account: anything that reaches the '
            .'connection already has everything. %s Grant only what the account uses; on an account '
            .'that genuinely needs breadth, the point of this finding is that it should have been a '
            .'decision rather than a default. This rule reads PRIVILEGES, not behavior — a clean '
            .'result does not mean the application cannot be injected, only that one consequence of '
            .'it is off the table.',
            $object->getString('grantee') ?? '?',
            $object->getString('target_type') ?? 'object',
            $object->getString('target') ?? '?',
            $this->breadthNote($object),
        );
    }

    /**
     * The sentence that separates a server-wide grant from one on a single database.
     *
     * Both are `ALL PRIVILEGES` and both are this rule, because severity is metadata on the rule and
     * splitting them would mean a second id for one fact. What differs is what the reader should
     * look at next, and that belongs in the message rather than in a second rule.
     */
    private function breadthNote(SchemaObject $object): string
    {
        $grantable = $object->getBool('grantable') === true;

        if (! $grantable) {
            return 'Every other limit configured on this server is a limit this account can ignore.';
        }

        // Grantable on top of everything is the one combination worth naming here: the account can
        // mint a SECOND account holding the same access, and the second one carries no record of
        // where it came from — so tomorrow's privilege audit sees an ordinary account instead of a
        // path. SEC.PRIV.GRANT_OPTION reports the handing-on itself; this names the combination.
        return 'It may also hand this on, so it can create a second account holding the same access '
            .'— one that carries no record of where it came from.';
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the catalog, not the connections: a privilege held by an account nothing ever authenticates as is the same rows as one in daily use',
            'follows the privileges the server records for this account, not the ones it reaches through membership in another role — an account privileged only by inheritance is a separate question the audit answers elsewhere',
            'cannot tell an over-grant from an account that is SUPPOSED to hold everything: an owner, a migration account, a backup role. The difference is in what the account is for, which lives outside the catalog',
        ];
    }
}
