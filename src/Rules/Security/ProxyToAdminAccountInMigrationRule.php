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
 * A migration that lets one account connect AS another — where the other one is the server's.
 *
 * `GRANT PROXY` is not a privilege over data or over the server. It is permission to **be somebody
 * else**: the proxying account authenticates with its own credential and then holds the proxied
 * account's privileges, not its own. So `GRANT PROXY ON 'root'@'localhost' TO 'app'@'%'` hands the
 * application a root session without ever naming a single administrative privilege.
 *
 * ## Why it needed its own rule rather than a row in the privilege list
 *
 * `PROXY` reads as administrative — 8.4 reports it under `Context = 'Server Admin'` — and the
 * obvious move was to add it to {@see MysqlAdminPrivileges}. That list describes names appearing in
 * a `GRANT … ON *.*` shape, and `PROXY` has no such shape: its object is an ACCOUNT.
 *
 * ```sql
 * GRANT PROXY ON 'proxied'@'host' TO 'proxy'@'host'   -- accepted
 * GRANT PROXY ON *.* TO 'proxy'@'host'                -- ERROR 1064, syntax
 * ```
 *
 * So an entry there could never have matched, and the arm that offers every listed name to a real
 * server would have stayed red forever. It sits in that artifact's `excluded` set, pointing here.
 *
 * ## ⚠️ It judges the TARGET, and a rule that reported every proxy would be switched off
 *
 * A proxy onto an equally unprivileged account is an ordinary authentication arrangement — that is
 * what the mechanism is for, and MySQL's own default row is one: measured on 8.4.10, a stock server
 * ships `root@localhost -> ''@''` in `mysql.proxies_priv`. Reporting the shape rather than the
 * target would put a finding on every installation on the day it was installed.
 *
 * So the rule fires when the **proxied** account is one the server owns (`mysql.`) or the
 * conventional superuser — the two a statement can recognize without a connection. See
 * {@see MysqlSystemAccounts} for why the prefix rather than a list of names.
 *
 * ## What this rule deliberately cannot see
 *
 * An arbitrary privileged account — `admin@%`, `deployer@10.%` — is invisible here, because nothing
 * in the statement says what it holds. That question needs the catalog, and answering it from a name
 * would be the guess this package refuses. The limitation is declared rather than left to be
 * discovered.
 *
 * ## Silent on PostgreSQL by grammar
 *
 * PostgreSQL has no `GRANT PROXY`. Its nearest equivalent is `SET ROLE` / role membership, which is
 * an ordinary `GRANT <role> TO <role>` and belongs to the rules that already read those. So a
 * PostgreSQL migration cannot produce this shape and the silence needs no driver check.
 */
final class ProxyToAdminAccountInMigrationRule extends AbstractMigrationSecurityRule
{
    /**
     * `GRANT PROXY ON <account> TO <account>`, with the proxied account's user part captured.
     *
     * The user part only: a host is `localhost`, `%` or an address, and none of them says anything
     * about privilege. Quoting is accepted in all three forms MySQL renders and people write —
     * single quotes in a migration, backticks in `SHOW GRANTS` output, and bare.
     */
    private const string PROXY_TARGET = '/\bGRANT\s+PROXY\s+\bON\b\s*[`\'"]?([^`\'"@\s]+)[`\'"]?\s*@/i';

    public function id(): string
    {
        return 'SEC.PRIV.PROXY_TO_ADMIN_IN_MIGRATION';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * High, where the administrative-privilege sibling is Medium, and the gap is the point.
     *
     * That rule reports an account acquiring one server power. This one reports an account acquiring
     * **every** power of another account, without naming any of them — a proxy onto root is a root
     * session. The severity does NOT vary with which administrative target it found, and the
     * limitations say so: `mysql.infoschema` carries no `SUPER` while `mysql.session` does, and both
     * report here at High because a project should be impersonating neither.
     */
    public function severity(): Severity
    {
        return Severity::High;
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
            'recognizes an administrative TARGET by name: the `mysql.` prefix the server uses for '
            .'its own accounts, and `root`. An arbitrary privileged account -- `admin@%` and the '
            .'like -- is invisible here, because a statement does not say what an account holds; '
            .'that question needs the catalog',
            '`root` is a CONVENTION, not a reserved name. An installation that renamed it is not '
            .'reported, and one whose `root` was replaced by an unprivileged placeholder is '
            .'reported anyway -- the name is what a statement offers',
            'reads one statement. A proxy granted outside a migration, or one already sitting in '
            .'`mysql.proxies_priv`, is not this rule\'s subject',
            'does not vary its severity with the target. `mysql.infoschema` holds no `SUPER` and '
            .'`mysql.session` does; both report at High, because a project account should be '
            .'impersonating neither',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;

        if (preg_match(self::PROXY_TARGET, $canonical, $match) !== 1) {
            return null;
        }

        $proxied = $match[1];

        if (! MysqlSystemAccounts::isAdministrative($proxied)) {
            return null;
        }

        return sprintf(
            'this migration grants PROXY on `%s` — %s. PROXY is not a privilege over data or over '
            .'the server: it is permission to CONNECT AS that account, so the grantee authenticates '
            .'with its own credential and then holds every privilege of `%s` rather than its own. '
            .'No administrative privilege is named anywhere in the statement, which is why this is '
            .'invisible to a review that reads privilege lists. Grant the data privileges the '
            .'application uses, and keep an operations account separate if one is genuinely needed. '
            .'Statement: %s',
            $proxied,
            MysqlSystemAccounts::describe($proxied),
            $proxied,
            StatementExcerpt::of($canonical),
        );
    }
}
