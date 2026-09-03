<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Pushery\SQLens\Catalog\Setting;
use Pushery\SQLens\Catalog\SettingsReading;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlServerSettingsReader;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The server settings a migration is about to run under, read instead of assumed.
 *
 * Rules reason about timeout hygiene from a distance: they see the statement, not the instance. At
 * the deploy moment the real values are one query away, and a value that makes the pending migration
 * dangerous should be a finding rather than an assumption nobody stated.
 *
 * ## The trap this check exists inside, and why it reads `reset_val`
 *
 * SQLens bounds its OWN session on purpose — `lock_timeout` and `statement_timeout` are set by the
 * session defense before any read happens. So `SHOW lock_timeout` inside a SQLens run answers with
 * SQLens' value, not the server's, and a check that believed it would report this package's hygiene
 * back to the project as its production configuration. Every judgment here therefore reads
 * {@see Setting::serverValue()}, which is `reset_val` on PostgreSQL: what a fresh session gets.
 *
 * Null there is never treated as a default. A value the reading could not establish is
 * `undetermined` with a reason, because judging a server against a compiled-in default while
 * believing you read the configuration is exactly the silent green this package exists to refuse.
 *
 * ## Why `lock_timeout = 0` is a finding here and not in `lint`
 *
 * Unbounded `lock_timeout` is an ordinary, defensible server setting. What makes it a finding is
 * WHEN this check runs: `sqlens:predeploy` runs immediately before `migrate --force`, so a DDL
 * statement is pending by construction. A DDL blocked behind a long transaction with no lock timeout
 * waits forever — and because `ALTER TABLE` queues an ACCESS EXCLUSIVE request, every read arriving
 * behind it queues too. The instance stops serving the table while nothing appears to be wrong.
 *
 * That is the whole reason these live in the deploy suite: the same value is fine on Tuesday and is
 * an outage at the moment a migration runs.
 *
 * ## Reading it never changes it
 *
 * This check reads. It does not set a server-level value, not even "just for this run" — the session
 * defense applies to SQLens' own connection and nothing else.
 */
final readonly class ServerSettingsCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.CONTEXT.SETTING';

    /**
     * PostgreSQL's compiled-in `max_wal_size`, in megabytes.
     *
     * Judged against the DEFAULT rather than against a computed need, and that is a deliberate
     * limit on the claim: how much WAL a rewrite produces depends on the table, and this check has
     * not been told which table. What it can say is that the instance is still on the shipped value
     * while a schema change is pending — which means checkpoints during a large rewrite, and a
     * rewrite that takes longer for a reason nobody will connect to this setting afterwards.
     *
     * @see https://www.postgresql.org/docs/18/runtime-config-wal.html
     */
    private const int DEFAULT_MAX_WAL_SIZE_MB = 1024;

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'pgsql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        // No try/catch here, and that is a measured decision rather than an oversight.
        // `PgsqlServerSettingsReader` catches everything internally and answers with
        // `SettingsReading::failed()`, so a catch around this call is a branch nothing can
        // enter — the coverage gate found it unreachable, which is what unreachable code
        // looks like from the outside. A dead catch is worse than none: it reads as though
        // somebody checked, and it would silently start swallowing the day the reader's
        // contract changes.
        $reading = new PgsqlServerSettingsReader($context->session)->read();

        // Read into a local, and asked about THAT. `succeeded()` says the same thing, but the
        // analyzer cannot see through it to the property — and a nullsafe here would quietly write
        // "could not be read ()" on the day the two disagree.
        if ($reading->failure instanceof UndeterminedReason) {
            return CheckResult::undetermined(
                self::ID,
                sprintf(
                    'the server settings could not be read (%s), so the timeouts this migration will '
                    .'run under are unknown. That is not the same as them being fine.',
                    $reading->failure->value,
                ),
            );
        }

        $findings = [];
        $unreadable = [];

        foreach ($this->judgments() as $name => $judge) {
            $setting = $reading->get($name);

            $reason = $this->unreadableReason($name, $setting, $reading);

            if ($reason !== null) {
                $unreadable[] = $reason;

                continue;
            }

            // Narrowed for the analyzer by the guard above: `unreadableReason()` returns a string
            // for every state in which either of these is null.
            $finding = $judge((string) $setting?->serverValue(), $context);

            if ($finding instanceof Finding) {
                $findings[] = $finding;
            }
        }

        // Fail-closed, and partially: the findings that WERE established still travel, because
        // throwing them away would make a run that saw three of four problems report none of them.
        // What the undetermined verdict says is that the check cannot claim the settings are fine —
        // which is a different sentence from "there is nothing here".
        if ($unreadable !== []) {
            return CheckResult::undetermined(
                self::ID,
                'setting_unreadable: '.implode('; ', $unreadable),
                $findings,
            );
        }

        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    /**
     * Why this setting could not be judged, or null when it can be.
     *
     * Three states, kept apart because they send a reader to three different places. A restricted
     * role loses whole rows from `pg_settings` silently — measured, 374 of 397 on PostgreSQL 18,
     * with no null and no error — so "absent" and "withheld" are genuinely different facts, and only
     * one of them is fixable with a GRANT.
     */
    private function unreadableReason(string $name, ?Setting $setting, SettingsReading $reading): ?string
    {
        if (! $setting instanceof Setting) {
            return $reading->absenceReason() instanceof UndeterminedReason
                // The reading saw everything and this name was not in it. On PostgreSQL that should
                // not happen for any of these four, so it is reported rather than shrugged off: a
                // build that renamed a setting would otherwise silently stop judging it.
                ? "`{$name}` could not be seen by the reading role, which is a privilege rather than "
                    .'a missing setting — the value may well be unsafe'
                : "`{$name}` is not in this server's settings at all, so it could not be judged";
        }

        if ($setting->serverValue() === null) {
            // The row exists and the value is withheld. PostgreSQL masks rather than failing for a
            // role without the privilege, so this is the state that most looks like an answer.
            return "`{$name}` is present but its value is withheld from the reading role, so what "
                .'this migration will run under is unknown';
        }

        return null;
    }

    /**
     * The settings this check judges, and what each verdict is.
     *
     * A map rather than a chain of methods, so the set is one readable list and adding a setting is
     * adding an entry. Order is the map's order, which makes two runs against one server produce the
     * findings in one sequence — a set iterated in container order would diff as a change.
     *
     * @return array<string, callable(string, PreflightContext): ?Finding>
     */
    private function judgments(): array
    {
        return [
            'lock_timeout' => fn (string $value, PreflightContext $context): ?Finding => $value !== '0' ? null : $this->finding(
                $context,
                'LOCK_TIMEOUT_UNBOUNDED',
                'lock_timeout',
                'The server runs with `lock_timeout = 0`, and a migration is about to run. A DDL '
                .'statement blocked behind a long-running transaction will wait indefinitely — and '
                .'because `ALTER TABLE` queues an ACCESS EXCLUSIVE request, every read arriving '
                .'behind it queues too. The table stops answering while nothing looks broken.',
                Severity::High,
                DowntimeClass::Blocking,
            ),
            'idle_in_transaction_session_timeout' => fn (string $value, PreflightContext $context): ?Finding => $value !== '0' ? null : $this->finding(
                $context,
                'IDLE_IN_TRANSACTION_UNBOUNDED',
                'idle_in_transaction_session_timeout',
                'The server runs with `idle_in_transaction_session_timeout = 0`. A session that '
                .'opened a transaction and went away holds its locks forever, and that is the single '
                .'most common thing a migration blocks behind. Nothing here says one exists — only '
                .'that if one does, nothing will end it.',
                Severity::Medium,
                DowntimeClass::Blocking,
            ),
            'statement_timeout' => fn (string $value, PreflightContext $context): ?Finding => $value !== '0' ? null : $this->finding(
                $context,
                'STATEMENT_TIMEOUT_UNBOUNDED',
                'statement_timeout',
                'The server runs with `statement_timeout = 0`. This is a common and defensible '
                .'setting, and it is reported rather than judged: it means a migration statement '
                .'that turns out to be far more expensive than expected has no upper bound of its '
                .'own, so the deploy ends when it ends.',
                Severity::Low,
                DowntimeClass::Online,
            ),
            'max_wal_size' => fn (string $value, PreflightContext $context): ?Finding => ! ctype_digit($value) || (int) $value > self::DEFAULT_MAX_WAL_SIZE_MB ? null : $this->finding(
                $context,
                'MAX_WAL_SIZE_AT_DEFAULT',
                'max_wal_size',
                sprintf(
                    'The server is still on the shipped `max_wal_size` (%s MB) while a schema change '
                    .'is pending. A table rewrite generates far more WAL than that, which forces '
                    .'checkpoints throughout — the rewrite takes longer and the I/O spike lands on '
                    .'everything else. Nothing here has measured your tables; this is the default '
                    .'being reported, not a computed need.',
                    $value,
                ),
                Severity::Low,
                DowntimeClass::Online,
                Confidence::Heuristic,
            ),
        ];
    }

    private function finding(
        PreflightContext $context,
        string $suffix,
        string $setting,
        string $message,
        Severity $severity,
        DowntimeClass $downtimeClass,
        Confidence $confidence = Confidence::Deterministic,
    ): Finding {
        return Finding::fail(
            ruleId: self::ID.'.'.$suffix,
            messagePrefix: DeployNotice::MESSAGE_PREFIX,
            message: $message,
            location: Location::inCatalog($context->driver, $context->connection, $setting, SchemaObjectType::Setting),
            category: Category::Safety,
            level: Level::Capturable,
            stability: StabilityTier::Stable,
            documentationUrl: RuleDocumentationUrl::for(self::ID.'.'.$suffix),
            context: new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false),
            severity: $severity,
        )->withDowntimeClass($downtimeClass)->withConfidence($confidence);
    }
}
