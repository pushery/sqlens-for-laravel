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
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
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
 * matters — is one of the tables THIS RUN touches in that state — and it is the only form of the
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
            $disabled = $this->disabledAmong($context, $targets);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                self::ID,
                'autovacuum_setting_unreadable: whether these tables carry a per-table autovacuum '
                .'override could not be read, so the estimates below cannot be qualified either '
                .'way: '.$failure->getMessage(),
            );
        }

        if ($disabled === []) {
            return CheckResult::pass(self::ID);
        }

        return CheckResult::fail(self::ID, array_map(
            fn (string $relation): Finding => $this->finding($context, $relation),
            $disabled,
        ));
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

                // Qualified, because the query joins pg_namespace and a bare name would match every
                // schema on a server that has more than one.
                $targets[] = $target->qualifiedName();
            }
        }

        return array_values(array_unique($targets));
    }

    /**
     * Which of those tables carry `autovacuum_enabled = false`.
     *
     * The read is three-valued and only one value comes back. `false` is the finding, `true` is
     * somebody being deliberate the other way, and ABSENT — the ordinary case — means the table runs
     * under the cluster setting. Filtering in SQL rather than in PHP keeps the third state from ever
     * needing a representation here: a boolean cast has no room for it, and the absent case is the
     * common one.
     *
     * @param  list<string>  $targets
     * @return list<string>
     */
    #[RawSql(reason: 'reads pg_class.reloptions through pg_options_to_table; a per-table storage parameter is a catalog fact with no model equivalent')]
    private function disabledAmong(PreflightContext $context, array $targets): array
    {
        $placeholders = implode(', ', array_fill(0, count($targets), '?'));

        $rows = $context->session->read(static fn (Connection $db): array => $db->select(
            'select n.nspname || \'.\' || c.relname as relation'
            .' from pg_class c'
            .' join pg_namespace n on n.oid = c.relnamespace'
            .' cross join lateral pg_options_to_table(c.reloptions) o'
            .' where c.relkind in (\'r\', \'m\', \'p\')'
            .' and o.option_name = \'autovacuum_enabled\''
            .' and lower(o.option_value) in (\'false\', \'off\', \'0\', \'n\', \'no\', \'f\')'
            .' and n.nspname || \'.\' || c.relname in ('.$placeholders.')'
            .' order by relation',
            $targets,
        ));

        $relations = [];

        foreach ($rows as $row) {
            $relation = (array) $row;
            $name = $relation['relation'] ?? null;

            if (is_string($name) && $name !== '') {
                $relations[] = $name;
            }
        }

        return $relations;
    }

    /** One table, and the two things its state costs this particular run. */
    private function finding(PreflightContext $context, string $relation): Finding
    {
        // A FAILURE rather than undetermined, and the distinction is the catalog's certainty. That
        // autovacuum is off is measured, not inferred — unlike the name-shaped checks beside it,
        // which report undetermined because a name is a heuristic. What is genuinely open is whether
        // somebody MEANT it, and that is answered by an ignore entry with a reason, which is how
        // this package silences a failure. Reporting it as undetermined would put the uncertainty
        // on the reading rather than on the intent, and the reading is not uncertain.
        return Finding::fail(
            ruleId: self::ID,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: sprintf(
                'This deploy touches `%s`, and autovacuum is switched off for that table '
                .'(`autovacuum_enabled = false` in its reloptions). Two things follow, and the '
                .'first is about this report rather than about the table. Dead rows are not '
                .'reclaimed, so the table\'s file size no longer predicts what a rewrite would '
                .'copy, and its row estimate goes stale with it — autovacuum is what triggers most '
                .'ANALYZE runs — which makes every duration and size stated here for this table the '
                .'least trustworthy figure in the report. Second, the setting DEFERS the vacuum '
                .'rather than avoiding it: once the table crosses autovacuum_freeze_max_age the '
                .'server starts an anti-wraparound worker on it regardless, and that worker does '
                .'not yield to a lock request. If this table is vacuumed by hand on a schedule, say '
                .'so with an ignore entry and the reason beside it — nothing in the catalog '
                .'separates a deliberate arrangement from a setting nobody revisited, so this is '
                .'reported rather than decided.',
                $relation,
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
