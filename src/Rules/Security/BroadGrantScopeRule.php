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
 * A MySQL grant whose SCOPE is a wildcard: the whole server, or a whole database.
 *
 * MySQL's `ON` clause names a scope rather than an object, and two of its shapes are wildcards.
 * `ON *.*` reaches every database on the server, including databases created after the migration
 * ran. `ON app.*` reaches every table in that database, including tables added later.
 *
 * That "including things that do not exist yet" is what separates this from a broad grant on a named
 * object, and it is why it has its own id rather than living under
 * {@see ExcessiveGrantRule}: that rule asks what was granted, this one asks over what. A project can
 * reasonably accept `GRANT SELECT ON reporting.*` to a read-only analytics account and still want to
 * hear about `GRANT ALL ON *.*` — with one id it could not.
 *
 * ## Why this is MySQL's question and PostgreSQL never asks it
 *
 * PostgreSQL has no `db.*` and no `*.*`. Its nearest equivalent is
 * `GRANT … ON ALL TABLES IN SCHEMA …`, which is a snapshot and does NOT reach tables added later —
 * a genuinely different guarantee, with `ALTER DEFAULT PRIVILEGES` as the separate construct for the
 * forward-looking case. So a PostgreSQL migration cannot produce the shape this rule matches, and
 * the silence is a property of the statement rather than of a driver check — which is what
 * {@see SecurityRuleSet} requires of a rule living in the shared set.
 */
final class BroadGrantScopeRule extends AbstractMigrationSecurityRule
{
    /**
     * `ON *.*` — the whole server.
     *
     * Backticks are allowed around the parts because MySQL accepts them and the canonical form does
     * not strip them; whitespace around the dot is accepted for the same reason.
     */
    private const string SERVER_WIDE = '/\bON\s+`?\*`?\s*\.\s*`?\*`?/i';

    /** `ON db.*` — every table in one database, including the ones added tomorrow. */
    private const string DATABASE_WIDE = '/\bON\s+`?([A-Za-z0-9_$]+)`?\s*\.\s*`?\*`?/i';

    public function id(): string
    {
        return 'SEC.PRIV.GRANT_SCOPE_BROAD_IN_MIGRATION';
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
            'cannot tell a deliberate database-wide grant from an accidental one: a read-only '
            .'analytics account over a reporting database is a legitimate use of `ON db.*`, and the '
            .'statement does not say which one this is',
            'reads the statement, not the server: a scope this migration narrows again later is '
            .'still reported, and privileges the account already held are not',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $canonical = $statement->canonical;

        if (! str_contains(strtoupper($canonical), 'GRANT')) {
            return null;
        }

        if (preg_match(self::SERVER_WIDE, $canonical) === 1) {
            return sprintf(
                'this migration grants privileges on `*.*` — every database on the server, including '
                .'databases that do not exist yet. An account with a server-wide grant is not scoped '
                .'to the application at all, so a compromise of it is a compromise of everything the '
                .'server hosts. Name the database and the tables the account actually uses. '
                .'Statement: %s',
                StatementExcerpt::of($canonical),
            );
        }

        if (preg_match(self::DATABASE_WIDE, $canonical, $match) === 1) {
            return sprintf(
                'this migration grants privileges on `%s.*` — every table in that database, '
                .'including tables added after this migration ran. A grant that keeps widening on '
                .'its own is one nobody reviews again: the next table inherits it silently. Name the '
                .'tables, or accept this id deliberately if the account is meant to follow the '
                .'schema. Statement: %s',
                $match[1],
                StatementExcerpt::of($canonical),
            );
        }

        return null;
    }
}
