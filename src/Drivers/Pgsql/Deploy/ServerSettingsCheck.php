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
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\Outcome;
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
 * ## Only a `high` finding stops the deploy — the rest travel beside a passing result
 *
 * The severities already draw the line, and the verdict follows it. `high` is the shape that ends
 * badly on its own: a DDL statement waiting on a lock nothing will end, with every read queued behind
 * it. `medium` and `low` make a bad day worse rather than making one, so they are `pass` findings —
 * named, with their value and their sentence, and not a reason to stop.
 *
 * Every finding used to block, and a consumer measured what that cost on a managed PostgreSQL. The
 * deploy stopped on `statement_timeout = 0`, which cannot be set server-wide without bounding the
 * very migration the deploy is about to run, and on `max_wal_size` at its default, which such a host
 * does not let anybody change. The messages below called both "reported rather than judged" the whole
 * time; only the verdict said otherwise.
 *
 * `idle_in_transaction_session_timeout = 0` sits below the line for a reason of its own. Its danger
 * reaches a migration only through a lock wait, and how long that wait may last is `lock_timeout`,
 * judged on its own right above it. Whether a session is holding a lock at this moment is a separate
 * reading, and a separate check.
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
                UndeterminedReason::SettingUnreadable,
                sprintf(
                    'the server settings could not be read (%s), so the timeouts this migration will '
                    .'run under are unknown. That is not the same as them being fine.',
                    $reading->failure->value,
                ),
            );
        }

        // Two lists rather than one, because they answer two questions: what stops this deploy, and
        // what it proceeds with. The failures lead the report, each list keeps the map's order, so
        // two runs against one server still produce one sequence.
        $blocking = [];
        $reported = [];
        $unreadable = [];

        // Whether anything is actually about to run. Read ONCE, here, rather than per judgment: the
        // four messages argue from the same fact, and two readings of one fact is two chances for a
        // report to contradict itself.
        $pending = ! $context->pending->isEmpty();

        foreach ($this->judgments() as $name => $judge) {
            $setting = $reading->get($name);

            $reason = $this->unreadableReason($name, $setting, $reading);

            if ($reason !== null) {
                $unreadable[] = $reason;

                continue;
            }

            // Narrowed for the analyzer by the guard above: `unreadableReason()` returns a string
            // for every state in which either of these is null.
            $verdict = $judge((string) $setting?->serverValue());

            if ($verdict === null) {
                continue;
            }

            // Sorted by the outcome the finding already carries, never by a second reading of the
            // severity: `finding()` decides once, and a list that re-derived it could disagree with
            // the finding it holds.
            $finding = $this->finding($context, $verdict, $pending);

            if ($finding->status->outcome === Outcome::Fail) {
                $blocking[] = $finding;
            } else {
                $reported[] = $finding;
            }
        }

        // Fail-closed, and partially: the findings that WERE established still travel, because
        // throwing them away would make a run that saw three of four problems report none of them.
        // What the undetermined verdict says is that the check cannot claim the settings are fine —
        // which is a different sentence from "there is nothing here".
        if ($unreadable !== []) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::SettingUnreadable,
                ''.implode('; ', $unreadable),
                [...$blocking, ...$reported],
            );
        }

        // A pass may carry findings, and here it carries two kinds: the not-applicable notices of a
        // run with nothing pending, and the settings below the line that a pending migration runs
        // under anyway. Both are named with their values; neither stops anything.
        return $blocking === []
            ? CheckResult::pass(self::ID, $reported)
            : CheckResult::fail(self::ID, [...$blocking, ...$reported]);
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
     * adding an entry. Order is the map's order within each outcome, failures first, which makes two
     * runs against one server produce the findings in one sequence — a set iterated in container
     * order would diff as a change.
     *
     * ## Each message is in two halves, and the reason is a false sentence somebody read
     *
     * The first half says what the setting IS and what it does. The second says what that means for
     * the change about to run — and only the second is true when a change is actually pending. A
     * consumer ran this gate after a deploy, with nothing pending, and read three findings arguing
     * from "a migration is about to run" in the same report whose first line said no migration was
     * read at all. A gate that refutes its own premise teaches a reader to treat the next real red
     * as noise.
     *
     * So with nothing pending the halves come apart: the state is reported as not-applicable, and
     * the premise sentence is left unsaid rather than asserted.
     *
     * @return array<string, callable(string): ?array{id: string, setting: string, state: string, pending: string, severity: Severity, downtime: DowntimeClass, confidence: Confidence}>
     */
    private function judgments(): array
    {
        return [
            'lock_timeout' => fn (string $value): ?array => $value !== '0' ? null : [
                'id' => 'DEPLOY.CONTEXT.SETTING.LOCK_TIMEOUT_UNBOUNDED',
                'setting' => 'lock_timeout',
                'state' => 'The server runs with `lock_timeout = 0`. A DDL statement blocked behind a '
                    .'long-running transaction will wait indefinitely — and because `ALTER TABLE` queues '
                    .'an ACCESS EXCLUSIVE request, every read arriving behind it queues too. The table '
                    .'stops answering while nothing looks broken.',
                'pending' => ' A migration is about to run under it.',
                'severity' => Severity::High,
                'downtime' => DowntimeClass::Blocking,
                'confidence' => Confidence::Deterministic,
            ],
            'idle_in_transaction_session_timeout' => fn (string $value): ?array => $value !== '0' ? null : [
                'id' => 'DEPLOY.CONTEXT.SETTING.IDLE_IN_TRANSACTION_UNBOUNDED',
                'setting' => 'idle_in_transaction_session_timeout',
                'state' => 'The server runs with `idle_in_transaction_session_timeout = 0`. A session '
                    .'that opened a transaction and went away holds its locks forever, and that is the '
                    .'single most common thing a migration blocks behind. Nothing here says one exists '
                    .'— only that if one does, nothing will end it.',
                'pending' => ' A migration is about to run, and how long it may wait behind such a session '
                    .'is `lock_timeout`, judged on its own.',
                'severity' => Severity::Medium,
                'downtime' => DowntimeClass::Blocking,
                'confidence' => Confidence::Deterministic,
            ],
            'statement_timeout' => fn (string $value): ?array => $value !== '0' ? null : [
                'id' => 'DEPLOY.CONTEXT.SETTING.STATEMENT_TIMEOUT_UNBOUNDED',
                'setting' => 'statement_timeout',
                'state' => 'The server runs with `statement_timeout = 0`. This is a common and '
                    .'defensible setting, and it is reported rather than judged: it means a statement '
                    .'that turns out to be far more expensive than expected has no upper bound of its '
                    .'own.',
                'pending' => ' For the migration about to run, that means the deploy ends when it ends.',
                'severity' => Severity::Low,
                'downtime' => DowntimeClass::Online,
                'confidence' => Confidence::Deterministic,
            ],
            'max_wal_size' => fn (string $value): ?array => ! ctype_digit($value) || (int) $value > self::DEFAULT_MAX_WAL_SIZE_MB ? null : [
                'id' => 'DEPLOY.CONTEXT.SETTING.MAX_WAL_SIZE_AT_DEFAULT',
                'setting' => 'max_wal_size',
                'state' => sprintf(
                    'The server is still on the shipped `max_wal_size` (%s MB). A table rewrite '
                    .'generates far more WAL than that, which forces checkpoints throughout — the '
                    .'rewrite takes longer and the I/O spike lands on everything else. Nothing here has '
                    .'measured your tables; this is the default being reported, not a computed need.',
                    $value,
                ),
                'pending' => ' A schema change is pending against it.',
                'severity' => Severity::Low,
                'downtime' => DowntimeClass::Online,
                'confidence' => Confidence::Heuristic,
            ],
        ];
    }

    /**
     * One finding for a setting: a failure, a reported pass, or a not-applicable notice.
     *
     * Decided here and nowhere else. With nothing pending the setting is not applicable, whatever
     * its severity. With a migration pending, `high` fails and everything below it is reported as a
     * pass — see the class note for where the line comes from.
     *
     * @param  array{id: string, setting: string, state: string, pending: string, severity: Severity, downtime: DowntimeClass, confidence: Confidence}  $verdict
     */
    private function finding(PreflightContext $context, array $verdict, bool $pending): Finding
    {
        $ruleId = $verdict['id'];
        $location = Location::inCatalog($context->driver, $context->connection, $verdict['setting'], SchemaObjectType::Setting);
        $subject = new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false);

        $finding = match (true) {
            $pending && $verdict['severity']->isAtLeast(Severity::High) => Finding::fail(
                ruleId: $ruleId,
                messagePrefix: DeployNotice::MESSAGE_PREFIX,
                message: $verdict['state'].$verdict['pending'],
                location: $location,
                category: Category::Safety,
                level: Level::Capturable,
                stability: StabilityTier::Stable,
                documentationUrl: RuleDocumentationUrl::for($ruleId),
                context: $subject,
                severity: $verdict['severity'],
            ),
            $pending => Finding::pass(
                ruleId: $ruleId,
                messagePrefix: DeployNotice::MESSAGE_PREFIX,
                message: $verdict['state'].$verdict['pending'],
                location: $location,
                category: Category::Safety,
                level: Level::Capturable,
                stability: StabilityTier::Stable,
                documentationUrl: RuleDocumentationUrl::for($ruleId),
                context: $subject,
                severity: $verdict['severity'],
            ),
            default => Finding::notApplicable(
                ruleId: $ruleId,
                messagePrefix: DeployNotice::MESSAGE_PREFIX,
                message: $verdict['state'],
                reason: NotApplicableReason::NothingPending,
                location: $location,
                category: Category::Safety,
                level: Level::Capturable,
                stability: StabilityTier::Stable,
                documentationUrl: RuleDocumentationUrl::for($ruleId),
                context: $subject,
                severity: $verdict['severity'],
            ),
        };

        return $finding->withDowntimeClass($verdict['downtime'])->withConfidence($verdict['confidence']);
    }
}
