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
 * A grant to a NAMED role that is permanently more than the role needs — or that lets it grant on.
 *
 * The sibling of {@see GrantToPublicRule}, and split from it deliberately. `PUBLIC` is a question
 * about the GRANTEE; this is a question about the PRIVILEGE. A team can legitimately accept one and
 * not the other — `GRANT USAGE ON SCHEMA reporting TO PUBLIC` is common and much less sharp than
 * `GRANT ALL PRIVILEGES ON orders TO app_runtime` — and with one id they could only silence both.
 *
 * ## The two shapes, and why the second one is the worse of them
 *
 * `ALL PRIVILEGES` is too much right, held forever. It is the shape somebody reaches for while
 * getting a migration to run, and it is invisible afterwards: read out of the catalog it looks like
 * a decision.
 *
 * `WITH GRANT OPTION` is smaller on the page and larger in effect. It does not widen what the role
 * may do — it makes the role able to widen what OTHERS may do, so the privilege set stops being
 * something the migration history describes. An audit of the catalog then answers "who granted
 * this?" with a role rather than a commit.
 *
 * ## Where it stays silent, and that silence is the specification
 *
 * - **Enumerated privileges to a named role.** `GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO
 *   app_runtime` is the target state the two-connection scaffold is written to produce. A rule that
 *   complained here would be arguing against its own remedy.
 * - **Grantee `PUBLIC`, including `GRANT ALL … TO PUBLIC`.** The sibling rule owns that statement
 *   whole. Two findings recommending the same fix is noise, and it doubles what a baseline has to
 *   carry for one line of SQL. `tests/Feature/Security/ExcessiveGrantRuleTest.php` holds the
 *   partition: exactly one of the two rules speaks for any given statement.
 *
 * ## The false positives this rule knowingly accepts
 *
 * A migration's OWNER role legitimately holds a great deal, and an extension's install script grants
 * broadly by design. Neither is distinguishable from an over-grant by reading the statement — the
 * difference is in what the role is FOR, which lives in a project's head and not in its SQL. So the
 * rule reports both and says so in {@see limitations()} rather than guessing at intent, and a
 * project that has made that decision silences the id.
 */
final class ExcessiveGrantRule extends AbstractMigrationSecurityRule
{
    /**
     * `ALL` optionally followed by `PRIVILEGES`, as a whole word.
     *
     * The boundary matters here for the same reason it does in the sibling rule: `ALLOW` and a
     * column named `all_access` are ordinary text, and a substring match would read either as the
     * keyword. Matched against the canonical form, so keyword casing and whitespace are already
     * normalized and the pattern is never chasing a formatter.
     */
    private const string ALL_PRIVILEGES = '/\bGRANT\s+ALL\b(?:\s+PRIVILEGES\b)?/i';

    /** The delegation clause. Trailing `;` and whitespace are already normalized away. */
    private const string GRANT_OPTION = '/\bWITH\s+GRANT\s+OPTION\b/i';

    /** The sibling rule's subject — matched here only in order to STAY QUIET. */
    private const string GRANTEE_PUBLIC = '/\bTO\s+PUBLIC\b/i';

    public function id(): string
    {
        return 'SEC.PRIV.GRANT_EXCESSIVE_IN_MIGRATION';
    }

    /**
     * Level 0, like every rule of this suite: what decides whether a security finding is reported is
     * `security.min_severity`, never strictness. A project running at level 0 is exactly the one
     * most likely to be granting `ALL PRIVILEGES` to get a deploy through.
     */
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
            'cannot tell an over-grant from a role that is SUPPOSED to hold everything: a migration '
            .'owner and an extension install script both grant broadly by design, and the '
            .'difference lives in what the role is for rather than in the statement',
            'reads the statement, not the server: a privilege this migration revokes again later is '
            .'still reported, and a privilege the role already held is not',
            'sees the grantee as a name, not as a role: it cannot know that the named role is itself '
            .'a member of something broader',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;

        if (! str_contains(strtoupper($canonical), 'GRANT')) {
            return null;
        }

        // The partition with the sibling rule. Checked BEFORE the privilege shapes, so
        // `GRANT ALL … TO PUBLIC` — which matches both — is answered by exactly one rule.
        if (preg_match(self::GRANTEE_PUBLIC, $canonical) === 1) {
            return null;
        }

        $delegable = preg_match(self::GRANT_OPTION, $canonical) === 1;
        $everything = preg_match(self::ALL_PRIVILEGES, $canonical) === 1;

        if (! $delegable && ! $everything) {
            return null;
        }

        return sprintf(
            'this migration %s. %s Grant the privileges the role actually uses, by name — '
            .'`GRANT SELECT, INSERT, UPDATE, DELETE ON … TO …` — and keep the account that runs '
            .'migrations separate from the one the application connects with. Statement: %s',
            $this->whatItDoes($everything, $delegable),
            $this->whyItMatters($delegable),
            StatementExcerpt::of($canonical),
        );
    }

    /** The finding's first clause: what the statement does, in the reader's terms. */
    private function whatItDoes(bool $everything, bool $delegable): string
    {
        if ($everything && $delegable) {
            return 'grants every privilege on the object AND the right to grant them on';
        }

        return $everything
            ? 'grants every privilege on the object'
            : 'grants the right to grant the privilege on to others';
    }

    /**
     * The second clause — why it is worth a finding, phrased per shape.
     *
     * Two sentences rather than one generic one, because the two shapes fail differently and a
     * reader deciding whether to accept this needs the specific reason. The severity stays uniform;
     * only the explanation varies, so nothing downstream branches on this text.
     */
    private function whyItMatters(bool $delegable): string
    {
        if ($delegable) {
            return 'A delegable grant takes the privilege set out of the migration history: from '
                .'here on, who holds what is decided at runtime by whoever holds this option, and a '
                .'later audit can no longer answer the question from the repository.';
        }

        return 'Read out of the catalog months later it is indistinguishable from a privilege '
            .'somebody arranged deliberately, so nobody removes it.';
    }
}
