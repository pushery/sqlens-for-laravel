<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Security\StatementExcerpt;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A MySQL grant whose grantee accepts connections from anywhere: `'app'@'%'`.
 *
 * In MySQL an account is a PAIR — the user name and the host it may connect from — and the host half
 * is a real access control, not documentation. `'app'@'10.0.1.5'` is an account that exists only for
 * connections from that address; `'app'@'%'` is the same credentials with that control removed.
 *
 * The credential then has to carry the whole defense on its own. That is the part worth saying out
 * loud, because it is what turns a leaked password from an incident into a breach: with a host
 * restriction, the leak is exploitable from inside the network; without one, from anywhere the
 * server is reachable.
 *
 * ## What it reports and what it does not
 *
 * A bare `'%'` is the full wildcard and always reported. A PARTIAL wildcard — `'10.0.%'`,
 * `'%.internal'` — is reported too, and deliberately: it looks like a restriction and MySQL
 * evaluates it as a pattern, so a reader who wrote `'%.example.com'` may not realize that a host
 * whose reverse lookup they do not control satisfies it. The message names which of the two it saw,
 * because they are worth different amounts of alarm.
 *
 * `localhost`, an address, and a name without a wildcard are all silent.
 *
 * ## Silent on PostgreSQL by data
 *
 * PostgreSQL grantees are roles, full stop — there is no `@host` half of a grantee to be a wildcard.
 * Its equivalent control lives in `pg_hba.conf`, which this suite judges through its own family of
 * rules against a live server. So a PostgreSQL migration cannot produce this shape, and the silence
 * falls out of the statement rather than out of a driver check.
 */
final class WildcardHostGranteeRule extends AbstractMigrationSecurityRule
{
    /**
     * A grantee's host half: `… TO 'user'@'host'`, in either quoting style MySQL accepts.
     *
     * Anchored on `TO` so a `DEFINER = 'x'@'%'` clause — a different fact, owned by the routine
     * rules — is not read as the grantee of this statement.
     */
    private const string GRANTEE_HOST = '/\bTO\s+(?:[\'"`][^\'"`]*[\'"`]|[A-Za-z0-9_$]+)\s*@\s*[\'"`]([^\'"`]*)[\'"`]/i';

    /**
     * The statement that CREATES the wildcard account, which is where it usually enters a project.
     *
     * A grant is where the account is USED; `CREATE USER 'app'@'%'` is where it is made, and a
     * migration that creates one and grants nothing yet is the same decision one statement earlier.
     * Anchored on `USER` rather than on a bare `@`, for the same reason the grant pattern is
     * anchored on `TO`: `CREATE DEFINER = 'x'@'%' … VIEW` carries an identical `@'%'` and is a
     * different fact with a different owner.
     *
     * `ALTER USER` and `RENAME USER` ride along — both can move an account onto a wildcard host,
     * and a rule that only watched creation would miss the migration that widens one later.
     *
     * Matched with `preg_match_all` rather than a single match, and that is not thoroughness for
     * its own sake: `RENAME USER 'a'@'localhost' TO 'a'@'%'` names TWO accounts, and a first-match
     * read lands on the one it is moving AWAY from. The rule would then stay silent on precisely
     * the statement that creates the wildcard — the failure being reported as the fix.
     */
    private const string ACCOUNT_STATEMENT = '/\A\s*(?:CREATE|ALTER|RENAME)\s+USER\b/i';

    /**
     * Every `@'host'` in a statement already known to be an account statement.
     *
     * Split from the lead check on purpose, and the split is the fix for a real defect. Anchoring
     * the lead INSIDE the per-account pattern meant `preg_match_all` found exactly one account:
     * after the first match the `RENAME USER` is consumed, and the second account no longer has it
     * in front. `RENAME USER 'a'@'localhost' TO 'a'@'%'` therefore reported `localhost` and stayed
     * silent — the statement that creates the wildcard read as the statement that fixes it.
     *
     * Anchoring the lead at the START of the statement also keeps the DEFINER exclusion intact:
     * `CREATE DEFINER = 'x'@'%' … VIEW` does not lead with CREATE USER, so it is never scanned.
     */
    private const string ACCOUNT_HOST = '/@\s*[\'"`]([^\'"`]*)[\'"`]/';

    public function id(): string
    {
        return 'SEC.PRIV.GRANT_WILDCARD_HOST_IN_MIGRATION';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    public function severity(): Severity
    {
        return Severity::Medium;
    }

    /** @return list<Suite> */
    #[Override]
    public function suites(): array
    {
        return [Suite::Lint, Suite::Security];
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'cannot know what the network already prevents: an account reachable only through a '
            .'private subnet or a proxy may be perfectly safe with `%`, and the statement says '
            .'nothing about what is in front of the server',
            'reads the grant, not the account: a host restriction applied by a separate '
            .'CREATE USER or RENAME USER statement is invisible to this one',
            'a containerized or serverless deployment often has no stable client address to name, '
            .'which is a real reason to accept this id rather than a reason to narrow the rule',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;
        $upper = strtoupper($canonical);

        // Two entry points, checked in the order a migration writes them: the account is created,
        // then granted to. Either alone is worth the finding — an account nobody has granted
        // anything to yet is still an account reachable from anywhere the moment somebody does.
        $hosts = [];

        if (preg_match(self::ACCOUNT_STATEMENT, $canonical) === 1 && preg_match_all(self::ACCOUNT_HOST, $canonical, $matches) > 0) {
            $hosts = $matches[1];
        } elseif (str_contains($upper, 'GRANT') && preg_match(self::GRANTEE_HOST, $canonical, $match) === 1) {
            $hosts = [$match[1]];
        }
        // The FIRST wildcard among the accounts, not the first account. A statement naming several
        // is worth the finding as soon as one of them is reachable from anywhere, and which one it
        // is belongs in the message rather than in the decision.
        $host = array_find(
            $hosts,
            static fn (string $candidate): bool => str_contains($candidate, '%') || str_contains($candidate, '_'),
        );

        if ($host === null) {
            return null;
        }

        return $host === '%'
            ? sprintf(
                'this migration names an account whose host is `%%` — it accepts connections '
                .'from anywhere the server is reachable. In MySQL the host half of an account is an '
                .'access control rather than a label, and removing it leaves the password carrying '
                .'the whole defense: a leaked credential becomes exploitable from outside the '
                .'network rather than only from inside it. Name the host, subnet or container '
                .'network the application connects from. Statement: %s',
                StatementExcerpt::of($canonical),
            )
            : sprintf(
                'this migration names an account whose host is `%s`, which MySQL evaluates as a '
                .'PATTERN rather than as a name. It reads like a restriction and is a wider one than '
                .'it looks: any host matching the pattern is accepted, including ones whose name you '
                .'do not control. Name the host or subnet exactly where you can. Statement: %s',
                $host,
                StatementExcerpt::of($canonical),
            );
    }
}
