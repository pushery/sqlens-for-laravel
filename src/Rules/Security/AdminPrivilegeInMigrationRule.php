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
 * A migration that grants an ADMINISTRATIVE MySQL privilege — one that governs the server, not data.
 *
 * `SELECT` on a table is a question about rows. `RELOAD`, `PROCESS`, `FILE` and the dynamic
 * privileges that replaced `SUPER` are questions about the SERVER: read every session's queries,
 * read and write files as the mysqld user, flush logs, change replication. An application account
 * needs none of them, and a migration is where one quietly acquires them — usually because a tool
 * asked for it once and nobody narrowed it afterwards.
 *
 * ## The privilege list is the shipped artifact, not a list in this file
 *
 * {@see MysqlAdminPrivileges} is reconciled against a REAL MySQL by its own test, and that
 * reconciliation has already earned itself: the list was written carrying `SET_USER_ID`, which 8.4
 * refuses outright — a rule holding that name would have matched nothing while looking exactly like
 * a rule with nothing to report. Copying the names into this rule would create the second source of
 * truth that mistake came from.
 *
 * ## Read from the privilege LIST, never from the whole statement
 *
 * The names are ordinary English words, and several are ordinary identifiers: `process`, `file`,
 * `reload` are all plausible table and column names. A rule matching them anywhere in the statement
 * would report `GRANT SELECT ON app.file_uploads TO …` — a false positive that is silent, constant,
 * and lands on the most innocuous statement in the migration.
 *
 * So the match happens only between `GRANT` and the `ON` that ends the privilege list. That is the
 * one region of a MySQL grant where a word is a privilege by grammar rather than by guess.
 *
 * ## Silent on PostgreSQL by data
 *
 * None of these names is a PostgreSQL privilege. Its administrative rights are role ATTRIBUTES
 * (`SUPERUSER`, `CREATEROLE`, `BYPASSRLS`) set by `CREATE ROLE`/`ALTER ROLE`, not privileges handed
 * out by `GRANT` — a different statement with its own rules already in this suite. So a PostgreSQL
 * migration cannot produce this shape, and the silence needs no driver check.
 */
final class AdminPrivilegeInMigrationRule extends AbstractMigrationSecurityRule
{
    /**
     * The privilege list of a MySQL grant: everything between `GRANT` and the `ON` that closes it.
     *
     * Non-greedy up to the first `ON` as a whole word, because a privilege list can contain commas,
     * column lists in parentheses and backticks — but never an unquoted `ON`.
     */
    private const string PRIVILEGE_LIST = '/\bGRANT\s+(.+?)\s+\bON\b/is';

    public function id(): string
    {
        return 'SEC.PRIV.GRANT_ADMIN_IN_MIGRATION';
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
            'reads the privilege list of one statement: a privilege the account already holds, or '
            .'one it inherits through a role, is invisible here — that is the audit suite\'s subject',
            'cannot tell an application account from an operations account. A backup or replication '
            .'user legitimately needs several of these, and the statement does not say which kind of '
            .'account this is',
            'judges the names the shipped artifact carries. A privilege MySQL adds in a later '
            .'version is not reported until that artifact is updated, which is why the artifact is '
            .'reconciled against a real server rather than maintained by hand',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;

        if (preg_match(self::PRIVILEGE_LIST, $canonical, $match) !== 1) {
            return null;
        }

        $granted = strtoupper($match[1]);
        $found = [];

        foreach (MysqlAdminPrivileges::judged() as $privilege) {
            // Word boundaries, because `FILE` must not match inside `FILE_UPLOADS` and `PROCESS`
            // must not match inside `PROCESS_QUEUE` — both are plausible column names in a
            // column-scoped grant, which lives inside this same region.
            if (preg_match('/\b'.preg_quote($privilege, '/').'\b/', $granted) === 1) {
                $found[] = $privilege;
            }
        }

        if ($found === []) {
            return null;
        }

        return sprintf(
            'this migration grants %s — %s that govern the SERVER rather than the data in it: '
            .'reading every session\'s queries, reading and writing files as the server process, '
            .'flushing logs, changing replication. An application account needs none of them. Grant '
            .'the data privileges the application uses, and keep an operations account separate if '
            .'one is genuinely needed. Statement: %s',
            implode(', ', $found),
            count($found) === 1 ? 'an administrative privilege' : 'administrative privileges',
            StatementExcerpt::of($canonical),
        );
    }
}
