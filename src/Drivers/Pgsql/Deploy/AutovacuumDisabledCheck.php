<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Illuminate\Database\Connection;
use Pushery\SQLens\Attributes\RawSql;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Drivers\Pgsql\Canonical\PgsqlCanonicalization;
use Pushery\SQLens\Drivers\Pgsql\Catalog\ApplicationSearchPath;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Throwable;

/**
 * A table this deploy touches that somebody switched autovacuum off for.
 *
 * ## Why the audit finding is not enough on its own
 *
 * `PG.L7.AUTOVACUUM_DISABLED` reports every such table in the database, which is the right shape for
 * an audit and the wrong one for a deploy: the list is read once, months ago, and a reader planning
 * a migration has no reason to go back to it. This check asks the narrower question at the moment it
 * matters — is one of the tables this run touches in that state — and it is the only form of the
 * question a deploy report can act on.
 *
 * ## What it changes about the deploy, and the first half is the one that surprises
 *
 * **The run's own estimates stand on sand.** A table without autovacuum keeps its dead rows, so its
 * file size stops predicting what a rewrite will copy, and its row estimate goes stale with it —
 * autovacuum is what triggers most `ANALYZE` runs. Every duration and size this report states about
 * that table is derived from exactly those two numbers, so they are quietly the least trustworthy
 * figures in it. That is a statement about the REPORT, which is why it belongs in the report.
 *
 * **And the vacuum arrives anyway.** The setting defers rather than avoids: once the table crosses
 * `autovacuum_freeze_max_age` the server starts an anti-wraparound worker on it regardless, and that
 * worker does not yield to a lock request. {@see FreezeHorizonCheck} measures how close that is;
 * this one says why the table got there.
 *
 * ## A server with autovacuum off is the same caveat for every table
 *
 * The per-table option is one way to stop autovacuum; `autovacuum = off` for the server is the
 * other, and it stops it for every table at once, the ones this run touches included. The check reads
 * the server setting beside the option, and where it is off every table the run touches carries the
 * caveat, with the server named as the reason. `PG.L7.AUTOVACUUM_OFF` reports the setting itself in
 * an audit; this check says what it means for the deploy at hand.
 *
 * ## A hand-maintained table is a real false positive, and `ignore` is its answer
 *
 * A table vacuumed in a window somebody chose is a legitimate arrangement, and nothing in the
 * catalog separates it from a setting nobody revisited. This check cannot see the cron, so it does
 * not try: the exemption is an `ignore` entry with the reason written beside it, never a heuristic
 * here guessing at intent from a name or a size. What it will not do is stay silent on the
 * possibility that the arrangement is deliberate — that would silence the common case to spare the
 * rare one.
 *
 * @see https://www.postgresql.org/docs/18/routine-vacuuming.html
 */
final readonly class AutovacuumDisabledCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.PREFLIGHT.AUTOVACUUM_DISABLED';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        // PostgreSQL only, and because InnoDB has no per-table equivalent rather than because nobody
        // wrote the MySQL half. `STATS_AUTO_RECALC` decides whether optimizer statistics are
        // refreshed, not whether dead rows are reclaimed, so reading it here would answer a
        // different question under this id.
        return $driver === 'pgsql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        // A run with no statements touches no table, and this check is about the tables a run is
        // about to touch rather than about the database's health.
        if ($context->pending->isEmpty()) {
            return CheckResult::pass(self::ID);
        }

        $targets = $this->targets($context);

        if ($targets === []) {
            return CheckResult::pass(self::ID);
        }

        try {
            $relations = $this->autovacuumAmong($context, $targets);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::AutovacuumSettingUnreadable,
                'whether autovacuum runs for these tables, by the server setting or by a per-table '
                .'override, could not be read, so the estimates below cannot be qualified either '
                .'way: '.new CredentialRedactor()->redact($failure->getMessage()),
            );
        }

        $findings = [];

        foreach ($relations as $relation) {
            if ($relation['table_off'] || $relation['server_off']) {
                $findings[] = $this->finding($context, $relation['relation'], $relation['table_off'], $relation['server_off']);
            }
        }

        return $findings === [] ? CheckResult::pass(self::ID) : CheckResult::fail(self::ID, $findings);
    }

    /**
     * The tables this run touches, whatever it does to them.
     *
     * Deliberately WIDER than the lock-shaped checks beside it, and the reason is the first of the
     * two consequences: a stale row estimate makes the report's numbers untrustworthy for any
     * statement whose cost it estimates, not only for one that takes an exclusive lock.
     *
     * Read from the statements' own resolved `targets` rather than re-parsed here — a second
     * classification is free to disagree with the one the report is built on.
     *
     * @return list<string>
     */
    private function targets(PreflightContext $context): array
    {
        $targets = [];

        foreach ($context->pending->statements as $statement) {
            foreach ($statement->targets ?? [] as $target) {
                if ($target->type !== SchemaObjectType::Table || ! $target->isSubject()) {
                    continue;
                }

                // The name as the migration wrote it, schema-qualified or bare. The query matches a
                // bare name only against the table an unqualified reference finds, so it cannot pick
                // up a table of the same name in another schema.
                // As the catalog holds it, because the query below compares it with `relname`.
                $targets[] = $target->catalogName(new PgsqlCanonicalization);
            }
        }

        return array_values(array_unique($targets));
    }

    /**
     * Each of those tables, with whether its own option and the server stop autovacuum for it.
     *
     * The per-table read is three-valued: `false` is the finding, `true` is somebody being
     * deliberate the other way, and ABSENT, the ordinary case, means the table runs under the server
     * setting. The EXISTS keeps the third state from needing a representation here: a table without
     * the option is simply not off by it. The server setting is read in the same statement, so one
     * round trip answers both, and `pg_settings` shows it to a role without privileges.
     *
     * @param  list<string>  $targets
     * @return list<array{relation: string, table_off: bool, server_off: bool}>
     */
    #[RawSql(reason: 'reads pg_class.reloptions through pg_options_to_table and the server setting from pg_settings; a storage parameter and a setting are catalog facts with no model equivalent')]
    private function autovacuumAmong(PreflightContext $context, array $targets): array
    {
        $placeholders = implode(', ', array_fill(0, count($targets), '?'));

        $rows = $context->session->read(static fn (Connection $db): array => $db->select(
            'select n.nspname || \'.\' || c.relname as relation,'
            .' exists (select 1 from pg_catalog.pg_options_to_table(c.reloptions) o'
            .' where o.option_name = \'autovacuum_enabled\''
            .' and pg_catalog.lower(o.option_value) in (\'false\', \'off\', \'0\', \'n\', \'no\', \'f\')) as table_off,'
            .' (select s.setting from pg_catalog.pg_settings s where s.name = \'autovacuum\') as server_setting'
            .' from pg_class c'
            .' join pg_namespace n on n.oid = c.relnamespace'
            .' where c.relkind in (\'r\', \'m\', \'p\')'
            // A bare target, as `Schema::table('orders', …)` writes it, matches the table an
            // unqualified reference finds; a qualified one matches by its composed name.
            .' and (n.nspname || \'.\' || c.relname in ('.$placeholders.')'
            .' or (c.relname in ('.$placeholders.') and '.ApplicationSearchPath::visible('c').'))'
            .' order by relation',
            [...$targets, ...$targets],
        ));

        $relations = [];

        foreach ($rows as $row) {
            $relation = (array) $row;
            $name = $relation['relation'] ?? null;

            if (! is_string($name) || $name === '') {
                continue;
            }

            $setting = $relation['server_setting'] ?? null;

            $relations[] = [
                'relation' => $name,
                'table_off' => in_array($relation['table_off'] ?? null, [true, 't', 1, '1'], true),
                // Only an explicit off stops it. A value the read could not see leaves the server's
                // part out of the verdict rather than putting it on every table.
                'server_off' => is_string($setting) && in_array(strtolower($setting), ['off', 'false', '0'], true),
            ];
        }

        return $relations;
    }

    /** One table, and the two things its state costs this particular run. */
    private function finding(PreflightContext $context, string $relation, bool $tableOff, bool $serverOff): Finding
    {
        $why = match (true) {
            $serverOff && $tableOff => 'autovacuum is switched off for the whole server (`autovacuum = off`), and the '
                .'table\'s own reloptions say `autovacuum_enabled = false` as well',
            $serverOff => 'autovacuum is switched off for the whole server (`autovacuum = off`), so no table is '
                .'vacuumed on its own, this one included',
            default => 'autovacuum is switched off for that table (`autovacuum_enabled = false` in its reloptions)',
        };
        $decide = match ($serverOff) {
            true => 'PG.L7.AUTOVACUUM_OFF reports the server setting itself, and until it is on again every table '
                .'this deploy touches carries the same caveat.',
            false => 'If this table is vacuumed by hand on a schedule, say so with an ignore entry and the reason '
                .'beside it — nothing in the catalog separates a deliberate arrangement from a setting nobody '
                .'revisited, so this is reported rather than decided.',
        };

        // A failure rather than undetermined, and the distinction is the catalog's certainty. That
        // autovacuum is off is measured, not inferred — unlike the name-shaped checks beside it,
        // which report undetermined because a name is a heuristic. What is genuinely open is whether
        // somebody meant it, and that is answered by an ignore entry with a reason, which is how
        // this package silences a failure. Reporting it as undetermined would put the uncertainty
        // on the reading rather than on the intent, and the reading is not uncertain.
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'This deploy touches `%s`, and %s. Two things follow, and the '
                .'first is about this report rather than about the table. Dead rows are not '
                .'reclaimed, so the table\'s file size no longer predicts what a rewrite would '
                .'copy, and its row estimate goes stale with it — autovacuum is what triggers most '
                .'ANALYZE runs — which makes every duration and size stated here for this table the '
                .'least trustworthy figure in the report. Second, the setting defers the vacuum '
                .'rather than avoiding it: once the table crosses autovacuum_freeze_max_age the '
                .'server starts an anti-wraparound worker on it regardless, and that worker does '
                .'not yield to a lock request. %s',
                $relation,
                $why,
                $decide,
            ),
            location: Location::inCatalog($context->driver, $context->connection, $relation, SchemaObjectType::Table),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: Severity::Medium,
        );
    }
}
