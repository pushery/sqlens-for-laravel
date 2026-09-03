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
 * A grant whose target is `PUBLIC` — every role in the database, present and future.
 *
 * `PUBLIC` is not a role somebody created; it is the implicit membership every role already has. A
 * grant to it therefore reaches accounts that do not exist yet, and it keeps reaching them. Read
 * later out of the catalog it is indistinguishable from a privilege somebody deliberately arranged,
 * which is why this rule speaks at the place the decision is written down rather than at the place
 * it is eventually noticed.
 *
 * ## Cut sharply at the grantee, and that is the whole point
 *
 * `GRANT ALL PRIVILEGES` to a NAMED role and `WITH GRANT OPTION` are both worth a finding and both
 * belong to a different id. Folding them in here would look tidier and would take something away: a
 * team that wants to accept `GRANT USAGE ON SCHEMA … TO PUBLIC` — common, and much less sharp than
 * `GRANT ALL ON TABLE … TO PUBLIC` — could then only silence it by blinding itself to the whole
 * family, and their baseline entries would not be separable either.
 *
 * So this rule answers exactly one question, and stays silent for a targeted grant to a named role
 * even when that grant is broad. The sibling rule owns that case.
 *
 * ## No path binding, deliberately
 *
 * A secrets rule binds itself to `database/migrations`, because a password literal in a seeder is
 * test data rather than a leak. A `GRANT … TO PUBLIC` is a finding wherever it is written — a seeder
 * that opens a table to every role opens it just as wide. The asymmetry is stated here so it is not
 * later "corrected" into a consistency nobody wanted.
 *
 * ## The severity is uniform, the message is not
 *
 * `USAGE ON SCHEMA` and `ALL ON TABLE` are both Medium, because a project's dial over this suite is
 * `security.min_severity` and a rule that graded itself would take that dial away. What the reader
 * needs in order to judge the difference is the privilege and the object, so the message carries
 * both rather than a verdict about how bad this particular one is.
 */
final class GrantToPublicRule extends AbstractMigrationSecurityRule
{
    /**
     * `\bPUBLIC\b` rather than a substring: `public_reader` and `publications` are ordinary names,
     * and an underscore is a word character — so the boundary is what keeps a named role called
     * `public_reader` from reading as the pseudo-role. Measured against the canonical form, which
     * has already normalized keyword casing and whitespace, so the pattern never chases a formatter.
     */
    private const string GRANTEE_PUBLIC = '/\bTO\s+PUBLIC\b/i';

    public function id(): string
    {
        return 'SEC.PRIV.GRANT_PUBLIC_IN_MIGRATION';
    }

    /**
     * Level 0, and that is the axis separation at its sharpest: a security rule must be reachable in
     * a run that asks for no strictness at all, because the projects that most need it are exactly
     * the ones running at a low level. What decides whether it is reported is
     * `security.min_severity`, never the level.
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
            'reads the statement, not the server: a grant this migration removes again a few '
            .'statements later is still reported, because the intent at the time of writing is what '
            .'the reader is being asked about',
            'says nothing about grants that already exist in the database — a live catalog is the '
            .'audit suite\'s subject, not a migration\'s',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;

        if (! str_contains(strtoupper($canonical), 'GRANT')) {
            return null;
        }

        if (preg_match(self::GRANTEE_PUBLIC, $canonical) !== 1) {
            return null;
        }

        return sprintf(
            'this migration grants %s to PUBLIC, which is not a role somebody created but the '
            .'membership every role in the database already has — including the ones that do not '
            .'exist yet. Read out of the catalog later it looks exactly like a privilege somebody '
            .'arranged on purpose. Grant to a named role instead, and keep the application account '
            .'separate from the account that runs migrations. Statement: %s',
            $this->privilegeAndObject($canonical),
            StatementExcerpt::of($canonical),
        );
    }

    /**
     * What was granted, and on what — the two facts a reader needs to judge how sharp this one is.
     *
     * Deliberately descriptive rather than parsed into a model: the severity is uniform, so nothing
     * downstream branches on this text, and a half-built grant parser would be a second thing that
     * can disagree with the canonicalizer about what a statement says.
     */
    private function privilegeAndObject(string $canonical): string
    {
        if (preg_match('/\bGRANT\s+(.+?)\s+ON\s+(.+?)\s+TO\s+PUBLIC\b/is', $canonical, $m) === 1) {
            return sprintf('%s on %s', trim($m[1]), trim($m[2]));
        }

        // `ALTER DEFAULT PRIVILEGES … GRANT … TO PUBLIC` and any other shape the pattern above does
        // not split. The finding still names the statement, so nothing is withheld from the reader.
        return 'privileges';
    }
}
