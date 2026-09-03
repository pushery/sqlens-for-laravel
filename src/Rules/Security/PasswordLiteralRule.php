<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Capture\ValueOrigin;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Security\OriginBinding;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A password written as a literal into a migration — the credential that is now in version control.
 *
 * `CREATE ROLE app_runtime LOGIN PASSWORD 'hunter2'` puts the password in the repository, in every
 * clone of it, in every CI log that echoes the migration, and in the reflog after somebody "removes"
 * it in a later commit. Rotating it means rotating it everywhere it was copied to, and nobody knows
 * where that is. It is the one finding in this suite that is Critical, because it is the one where
 * the damage is already done by the time it is read.
 *
 * ## Path-bound, and the binding is the whole design
 *
 * The identical statement means three different things depending on where it is written, so this
 * rule answers three different ways:
 *
 * - **In a migration** — Critical. It runs against the real database, and the credential it sets is
 *   a real one.
 * - **In a seeder or a factory** — silence. That is test data. A rule that shouted here would be
 *   wrong on the overwhelming majority of the literals in a repository, and a rule that is usually
 *   wrong gets switched off — taking the migration case with it.
 * - **Origin unknown** — `undetermined`, with the reason named. A snippet judged without a file behind it has no origin. Passing would hide a real leak; a Critical would fire on evidence the run does
 *   not have.
 *
 * The binding arrives already decided on {@see MigrationStatementView::$originBinding}, resolved
 * once per run from the paths the framework actually migrates from. This rule never inspects a path
 * itself — a rule that did would reach for `database/migrations` and miss a package path, a tenant
 * subdirectory, and be fooled by a seeder named like a migration.
 *
 * ## The value NEVER appears in the finding
 *
 * Not the literal, not a prefix, not a length, not a hash. A finding travels into a JSON report, a
 * SARIF file, a CI annotation and an agent artifact — several of which are committed or uploaded —
 * so a rule that quoted the secret would republish it into more places than the migration did, in
 * the name of reporting it. The message names the STATEMENT SHAPE and the account, which is what
 * somebody needs in order to find and rotate it.
 *
 * That is also why this rule does not carry the usual `Statement: …` excerpt its siblings do: the
 * excerpt would contain the literal. The location — file, line, migration class — is how a reader
 * gets there instead.
 */
final class PasswordLiteralRule extends AbstractMigrationSecurityRule
{
    /**
     * A password clause with a LITERAL after it.
     *
     * `PASSWORD` optionally preceded by `ENCRYPTED` — PostgreSQL accepts both spellings and they
     * mean the same thing here, since what matters is that the plaintext was typed into the file.
     * The literal itself is captured only so the pattern can require one; it is never read out.
     */
    private const string PASSWORD_LITERAL = "/\\b(?:ENCRYPTED\\s+)?PASSWORD\\s+'/i";

    /**
     * MySQL's spelling of the same thing — `IDENTIFIED BY '<literal>'`.
     *
     * One rule covers both engines, and that is the architecture rather than a shortcut: both
     * drivers append the identical {@see SecurityRuleSet}, so a second, MySQL-only rule would still
     * be constructed under PostgreSQL and stay silent forever — an engine claim made by a rule,
     * which is exactly what the core-purity rule exists to prevent. Here the silence falls out of
     * the STATEMENT: PostgreSQL has no `IDENTIFIED BY` clause, MySQL has no `CREATE ROLE … PASSWORD`.
     *
     * Three forms, and the optional groups are each a real MySQL spelling:
     *
     * - `IDENTIFIED BY 'x'` — the ordinary one.
     * - `IDENTIFIED WITH <plugin> BY 'x'` — an account pinned to an auth plugin.
     * - `IDENTIFIED BY PASSWORD '<hash>'` — retired in 8.4, but an old migration still says it, and
     *   a hash in version control is a secret in version control.
     *
     * ## What it deliberately does NOT match, and why each one would have been a bad alarm
     *
     * `IDENTIFIED WITH auth_socket` and `IDENTIFIED WITH caching_sha2_password` set no literal at
     * all — the plugin decides. Requiring `BY` followed by a quote keeps them out.
     *
     * `IDENTIFIED BY RANDOM PASSWORD` is MySQL 8's generated-password form, which is the shape this
     * rule RECOMMENDS: the value never appears in the statement. After `BY` comes `RANDOM`, not a
     * quote and not `PASSWORD '`, so it does not match — and it must not, because a false alarm on
     * the recommended shape is what gets an id silenced along with its true findings.
     */
    private const string IDENTIFIED_BY_LITERAL = "/\\bIDENTIFIED\\s+(?:WITH\\s+\\S+\\s+)?BY\\s+(?:PASSWORD\\s+)?'/i";

    /**
     * `SET PASSWORD [FOR '<user>'@'<host>'] = '<literal>'` — MySQL's third way to set one.
     *
     * Anchored on the assignment rather than on the word, so `SET PASSWORD FOR … = RANDOM()` or any
     * future non-literal right-hand side stays quiet. The `FOR` clause carries an account name in
     * quotes, which is why the pattern looks for the `=` first: without it, the account's own quotes
     * would read as the credential.
     */
    private const string SET_PASSWORD_LITERAL = "/\\ASET\\s+PASSWORD\\b[^=]*=\\s*'/i";

    /**
     * The statements that SET a password, as opposed to merely mentioning the word.
     *
     * Anchored on the statement lead so a `COMMENT ON … IS 'the password column'` or an ordinary
     * insert into a column called `password` cannot reach the check above. Those contain the word
     * and set no credential, and reporting them would make the rule noise on exactly the projects
     * that store hashed passwords properly.
     */
    private const string ROLE_STATEMENT = '/\A\s*(?:(?:CREATE|ALTER)\s+(?:USER|ROLE|GROUP)\b|SET\s+PASSWORD\b)/i';

    public function id(): string
    {
        return 'SEC.AUTH.PASSWORD_LITERAL_IN_MIGRATION';
    }

    /** Level 0 like the rest of the suite: gated by `security.min_severity`, never by strictness. */
    public function level(): Level
    {
        return Level::Capturable;
    }

    /**
     * The only Critical this package reports on a migration.
     *
     * Deliberately above the grant rules, and the difference is recoverability. An over-broad grant
     * is a state somebody can narrow; a password in version control is an event that already
     * happened, and narrowing it is not one of the available moves.
     */
    public function severity(): Severity
    {
        return Severity::Critical;
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
            'reads the statement, not the repository: a password committed once and removed in a '
            .'later migration is still in the history, and this rule sees only the migration it is '
            .'looking at',
            'cannot tell a real credential from a placeholder. A migration that sets a throwaway '
            .'password for a role it drops three statements later is reported the same way, because '
            .'the statement does not say which one it is',
            'says nothing about a password supplied through a binding or an environment variable — '
            .'which is the recommended shape, and is invisible here precisely because the value '
            .'never becomes part of the statement',
            'stays quiet about a literal that shares its statement with a binding. The value-origin '
            .'marker answers per STATEMENT, not per value, so `… PASSWORD \'x\' … WHERE id = ?` '
            .'reads as bound. That is the deliberate direction to be wrong in: a false alarm on the '
            .'shape this rule recommends would get the whole id silenced, taking the true findings '
            .'with it',
        ];
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        $canonical = $statement->canonical;

        if (preg_match(self::ROLE_STATEMENT, $canonical) !== 1) {
            return null;
        }

        // Any of the three spellings is the same finding. They are separate constants rather than
        // one alternation because each carries its own false-positive reasoning, and a single
        // pattern would hide which of them a future edit widened.
        $setsLiteral = preg_match(self::PASSWORD_LITERAL, $canonical) === 1
            || preg_match(self::IDENTIFIED_BY_LITERAL, $canonical) === 1
            || preg_match(self::SET_PASSWORD_LITERAL, $canonical) === 1;

        if (! $setsLiteral) {
            return null;
        }

        // Where the VALUE came from, before where the STATEMENT came from — because this is the
        // check that decides whether there is anything to report at all.
        //
        // Measured, and it is why this rule was not shippable before the marker existed: a binding
        // and a hard-coded literal are the same canonical text by the time a rule sees them, so a
        // rule reading only the text reports the shape it RECOMMENDS. The fixture pair proved it —
        // the good half used a binding and tripped the rule.
        if ($statement->valueOrigin === ValueOrigin::AllValuesBound) {
            return null;
        }

        if ($statement->valueOrigin === ValueOrigin::Undeterminable) {
            return RuleVerdict::undetermined(
                'this statement sets a password, and this run cannot tell whether the value was '
                .'written into the file or supplied at the call site. The two are the same text by '
                .'the time a rule reads them, and the capture that would have said which never '
                .'reached this statement. Reporting it would risk a Critical on the recommended '
                .'shape; passing it would hide a credential in version control.',
                UndeterminedReason::ValueOriginUnknown,
            );
        }

        // The path binding, and the order matters: the statement is only judged once it is known to
        // BE the shape this rule is about. Answering `undetermined` for every snippet that merely
        // has no origin would fill a run with reasons about statements this rule would have ignored
        // anyway.
        return match ($statement->originBinding) {
            OriginBinding::Migration => RuleVerdict::flag($this->message()),
            OriginBinding::NotAMigration => null,
            OriginBinding::Unknown => RuleVerdict::undetermined(
                'this statement sets a password from a literal, and this run cannot tell whether it '
                .'came from a migration or from a seeder. In a migration it is a credential now in '
                .'version control; in a seeder it is test data. The run has no file to attribute '
                .'the statement to — a snippet judged on its own has none — so neither answer is '
                .'available and neither is assumed.',
                UndeterminedReason::OriginUnknown,
            ),
        };
    }

    /**
     * The finding text — deliberately without the statement.
     *
     * Every sibling rule ends on `Statement: …`, and this one must not: the excerpt would carry the
     * literal into the JSON report, the SARIF file, the CI annotation and the agent artifact. A
     * rule that republished the secret in the course of reporting it would put it in more places
     * than the migration did.
     */
    private function message(): string
    {
        return 'this migration sets a password from a literal written into the file. The credential '
            .'is now in version control — in every clone, in the reflog after it is "removed" in a '
            .'later commit, and in any CI log that echoed the migration — so rotating it means '
            .'rotating it everywhere it was copied to, and nobody knows where that is. Supply it '
            .'through a binding or an environment read instead, so the value never becomes part of '
            .'the statement. The value itself is deliberately not shown here; the location above is '
            .'how to find it.';
    }
}
