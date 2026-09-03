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
 * A `SECURITY DEFINER` routine created without pinning its `search_path`.
 *
 * The routine runs with the privileges of whoever OWNS it rather than whoever calls it — usually the
 * migration role, which usually holds a great deal. That is the whole point of `SECURITY DEFINER`
 * and it is fine. What is not fine is leaving the name resolution to the caller: `search_path` is a
 * session setting, so an unqualified `orders` inside the body means whatever the CALLER's path says
 * it means. A caller who can create a table in a schema earlier on that path decides what the
 * privileged routine executes.
 *
 * The escalation needs nothing exotic — no injection, no bug in the function. It needs a
 * `CREATE TABLE` in a schema the caller controls and a call to a function that was never told where
 * to look.
 *
 * ## High, and the only rule of this family that is
 *
 * Its catalog siblings — {@see RoutineDefinerRule}, {@see RoutineDefinerMutablePathRule},
 * {@see RoutineDefinerUnsafePathRule} — are Medium: they find a routine that already exists and ask
 * increasingly specific questions about the path it pinned. This one finds the moment the routine is
 * WRITTEN with no path at all, which is both the sharpest form and the only one that is still a
 * decision somebody can change by editing a file.
 *
 * ## Silent on MySQL by DATA, not by a driver check
 *
 * `SecurityRuleSet` is appended by both drivers on purpose, and its docblock states the rule: an
 * engine a rule has nothing to say on must fall out of what the statement CONTAINS, so silence is a
 * property of the data rather than a per-driver list somebody has to remember to update.
 *
 * That holds here without needing an exception. MySQL routines are declared `SQL SECURITY DEFINER`;
 * PostgreSQL's is `[EXTERNAL] SECURITY DEFINER`, never with `SQL` in front. So the rule stands down
 * on any statement carrying `SQL SECURITY`, and every MySQL routine falls out — which is correct
 * rather than merely convenient, because MySQL has no `search_path` and the question this rule asks
 * does not exist there. MySQL's own definer risk is a different question with a different answer,
 * and it does not belong under this id.
 *
 * The exclusion is a check of its own rather than a lookbehind on the pattern beside it, and the
 * reason is in that constant's docblock: PCRE lookbehind is fixed-width, so the tidy spelling would
 * have silenced `SQL SECURITY` and not `SQL  SECURITY`.
 */
final class DefinerWithoutSearchPathRule extends AbstractMigrationSecurityRule
{
    /**
     * The clause this rule is about. `EXTERNAL SECURITY DEFINER` — valid PostgreSQL for a
     * C-language function — matches too, correctly.
     */
    private const string SECURITY_DEFINER = '/\bSECURITY\s+DEFINER\b/i';

    /**
     * MySQL's spelling, matched only in order to stand down.
     *
     * Written as its own check rather than as a lookbehind on the pattern above, because PCRE
     * lookbehind is fixed-width and `SQL\s+` is not: the tidy-looking `(?<!SQL\s)` would silently
     * fail to exclude `SQL  SECURITY DEFINER`, and a rule firing on every MySQL routine would be
     * both wrong and loud. Two named checks cost one line and cannot do that.
     */
    private const string MYSQL_SQL_SECURITY = '/\bSQL\s+SECURITY\b/i';

    /**
     * A pinned path, in either spelling PostgreSQL accepts.
     *
     * `SET search_path = …` and `SET search_path TO …` are the same clause. Whether the value is a
     * SAFE path is a different question, and it belongs to the catalog siblings — a rule that
     * answered both would have no separate id to silence.
     */
    private const string PINS_SEARCH_PATH = '/\bSET\s+search_path\s*(?:=|\bTO\b)/i';

    public function id(): string
    {
        return 'SEC.PRIV.ROUTINE_DEFINER_NO_PATH_IN_MIGRATION';
    }

    /** Level 0 like the rest of the suite: gated by `security.min_severity`, never by strictness. */
    public function level(): Level
    {
        return Level::Capturable;
    }

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
            'reads the statement, not the body: a routine whose every reference is already '
            .'schema-qualified is safe in practice and is still reported, because whether the next '
            .'edit stays qualified is not something the statement can promise',
            'does not judge the path that IS pinned — a routine that names a writable schema '
            .'satisfies this rule and is the subject of SEC.PRIV.ROUTINE_DEFINER_UNSAFE_PATH',
            'says nothing about routines that already exist in the database; a live catalog is the '
            .'audit suite\'s subject',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;

        // MySQL first: its routines are always `SQL SECURITY {DEFINER|INVOKER}`, and it has no
        // search_path for this rule to ask about. Standing down here is what keeps the silence a
        // property of the statement rather than of a driver check the ruleset deliberately avoids.
        if (preg_match(self::MYSQL_SQL_SECURITY, $canonical) === 1) {
            return null;
        }

        if (preg_match(self::SECURITY_DEFINER, $canonical) !== 1) {
            return null;
        }

        if (preg_match(self::PINS_SEARCH_PATH, $canonical) === 1) {
            return null;
        }

        return sprintf(
            'this migration creates a SECURITY DEFINER routine without pinning its search_path. The '
            .'routine runs with its OWNER\'s privileges — here, the role that runs migrations — '
            .'while an unqualified name inside it resolves against the CALLER\'s search_path. A '
            .'caller who can create an object in a schema earlier on their path therefore chooses '
            .'what the privileged routine executes, and needs no injection to do it. Add a '
            .'SET search_path clause naming only schemas the owner controls (and schema-qualify what '
            .'the body touches), or declare the routine SECURITY INVOKER if it does not need the '
            .'owner\'s rights. The rule\'s page carries the exact clause. Statement: %s',
            StatementExcerpt::of($canonical),
        );
    }
}
