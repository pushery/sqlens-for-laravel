<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Catalog\Setting;
use Pushery\SQLens\Catalog\SettingsReading;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Drivers\Pgsql\Catalog\DurationValue;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlRoleDefaultsReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlServerSettingsReader;
use Pushery\SQLens\Drivers\Pgsql\Catalog\RoleDefaults;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\StrongLockStatements;
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
use Pushery\SQLens\Subjects\MigrationDirection;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
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
 * back to the project as its production configuration. The judgments therefore read
 * {@see Setting::serverValue()}, which is `reset_val` on PostgreSQL: what a fresh session gets.
 *
 * Null there is never treated as a default. A value the reading could not establish is
 * `undetermined` with a reason, because judging a server against a compiled-in default while
 * believing you read the configuration is exactly the silent green this package exists to refuse.
 *
 * ## Whose fresh session: `lock_timeout` is read for the role the migrations run as
 *
 * `reset_val` answers for the role that reads it, and a preflight reads through an account of its
 * own. A default stored with `ALTER ROLE … SET` reaches only the role it names, so the reading role
 * can start bounded while the migration role waits forever, and the other way round. For the one
 * judgment that stops the deploy that difference is the verdict, so `lock_timeout` is read from the
 * defaults stored in `pg_db_role_setting`: the migration role's own, then the one for this database
 * or for every role, then the server's value, which `reset_val` shows only while the reading role has
 * no default of its own. A value this reading cannot see is `undetermined`, never the reading role's
 * value put in its place.
 *
 * Then the pending statements are read, as the MySQL sibling reads its own bound: a migration that
 * sets `lock_timeout` before its first strong lock, as `PG.L3.MISSING_LOCK_TIMEOUT` asks, does not
 * wait under the role's value, and the finding then travels as an `info` note beside a passing result.
 *
 * The three settings below the line read `reset_val` as it is: what a fresh session of the reading
 * role starts with, which is the server's value while that role has no default of its own.
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

        // The stored defaults, for the one judgment read for the role the migrations run as.
        $defaults = new PgsqlRoleDefaultsReader($context->session)->read();

        foreach ($this->judgments() as $name => $judge) {
            $setting = $reading->get($name);

            $reason = $this->unreadableReason($name, $setting, $reading);

            if ($reason !== null) {
                $unreadable[] = $reason;

                continue;
            }

            // Narrowed for the analyzer by the guard above: `unreadableReason()` returns a string
            // for every state in which either of these is null.
            $start = $name === 'lock_timeout'
                ? $this->migrationStart((string) $setting?->serverValue(), $defaults, $context->migrationRole)
                : ['value' => (string) $setting?->serverValue()];

            if (isset($start['unknown'])) {
                $unreadable[] = $start['unknown'];

                continue;
            }

            $verdict = $judge($start['value'], $context);

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
     * @return array<string, callable(string, PreflightContext): ?array{id: string, setting: string, state: string, pending: string, severity: Severity, downtime: DowntimeClass, confidence: Confidence}>
     */
    private function judgments(): array
    {
        return [
            'lock_timeout' => fn (string $value, PreflightContext $context): ?array => $value !== '0' ? null : $this->lockTimeoutVerdict($context),
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
     * The `lock_timeout` a fresh session of the role the migrations run as starts with, in
     * milliseconds, or the clause saying why this reading cannot tell.
     *
     * The role's own default first, then the default of this database or of every role, then the
     * server's value. `reset_val` is the server's value only while the reading role carries no default
     * of its own, because that default is what `reset_val` would show; and with no migration role
     * configured it stands for every role only while none carries one.
     *
     * @return array{value: string}|array{unknown: string}
     */
    private function migrationStart(string $readerValue, RoleDefaults $defaults, ?string $role): array
    {
        if (! $defaults->read) {
            return ['unknown' => 'the defaults stored per role and database could not be read, so the '
                .'`lock_timeout` the migrations start with is unknown'];
        }

        $owners = $defaults->rolesWithOwn('lock_timeout');

        if ($role === null && $owners !== []) {
            return ['unknown' => sprintf(
                'the role the migrations run as is not configured, and %s %s, so which value the migrations '
                .'start with is unknown',
                implode(', ', array_map(static fn (string $owner): string => '`'.$owner.'`', $owners)),
                count($owners) === 1 ? 'carries a `lock_timeout` default of its own' : 'carry `lock_timeout` defaults of their own',
            )];
        }

        $stored = ($role === null ? null : $defaults->own($role, 'lock_timeout')) ?? $defaults->shared('lock_timeout');

        if ($stored === null && in_array($defaults->reader, $owners, true)) {
            return ['unknown' => sprintf(
                '`%s`, the role this check reads as, carries a `lock_timeout` default of its own, which '
                .'hides the server\'s value, and `%s`, the role the migrations run as, has none',
                $defaults->reader,
                (string) $role,
            )];
        }

        if ($stored === null) {
            return ['value' => $readerValue];
        }

        // Stored as it was written, `10s` rather than `10000`, so it is read the way the server reads it.
        $milliseconds = DurationValue::milliseconds($stored);

        return $milliseconds === null
            ? ['unknown' => "the stored default `lock_timeout = {$stored}` is not a duration this check can read"]
            : ['value' => (string) $milliseconds];
    }

    /**
     * The finding for a migration role that starts with `lock_timeout = 0`, weighed against what the
     * pending migrations set for themselves.
     *
     * It stops the deploy when a pending statement would wait under that value, or when the statements
     * handed over are not all the deploy runs and nothing can say whether one would. Otherwise the value
     * is still reported, as an `info` note.
     *
     * @return array{id: string, setting: string, state: string, pending: string, severity: Severity, downtime: DowntimeClass, confidence: Confidence}
     */
    private function lockTimeoutVerdict(PreflightContext $context): array
    {
        [$unbounded, $locking] = $this->lockWaitsIn($context->pending->statements);

        // Nothing pending bounds nothing: the notice of such a run keeps the severity of the value, and
        // `finding()` leaves the premise below unsaid.
        $bounded = ! $context->pending->isEmpty() && ! $unbounded instanceof CapturedStatement && $context->pending->statementsComplete;

        $pending = match (true) {
            $unbounded instanceof CapturedStatement => sprintf(
                ' A migration is about to run under it: a statement on %s takes a strong lock before its '
                .'session sets a `lock_timeout` of its own.',
                $this->tablesOf($unbounded),
            ),
            ! $bounded => ' A migration is about to run under it, and the statements handed to this check are '
                .'not all the deploy runs, so nothing here can say whether it sets its own bound first.',
            $locking === 0 => ' No pending statement takes a strong lock on a table that already exists, so '
                .'nothing in this deploy waits under it.',
            default => ' The pending migrations do not wait under it: each statement that takes a strong lock '
                .'on a table that already exists runs after its session sets a `lock_timeout` of its own.',
        };

        $freshSession = match ($context->migrationRole === null) {
            true => 'The role the migrations run as is not configured, and a fresh session of any role on this '
                .'database starts with `lock_timeout = 0`: none carries a default of its own.',
            false => sprintf(
                'A fresh session of `%s`, the role the migrations run as, starts with `lock_timeout = 0`.',
                $context->migrationRole,
            ),
        };

        return [
            'id' => 'DEPLOY.CONTEXT.SETTING.LOCK_TIMEOUT_UNBOUNDED',
            'setting' => 'lock_timeout',
            'state' => $freshSession
                .' A DDL statement blocked behind a long-running transaction will wait indefinitely — and '
                .'because `ALTER TABLE` queues an ACCESS EXCLUSIVE request, every read arriving behind it '
                .'queues too. The table stops answering while nothing looks broken.',
            'pending' => $pending,
            'severity' => $bounded ? Severity::Info : Severity::High,
            'downtime' => $bounded ? DowntimeClass::Online : DowntimeClass::Blocking,
            'confidence' => Confidence::Deterministic,
        ];
    }

    /**
     * The first pending statement that would wait under the role's `lock_timeout`, and how many
     * statements take a strong lock on a table that already exists.
     *
     * Read in the order the deploy runs them, and per connection. A `SET lock_timeout` bounds the
     * session that ran it for every later statement on it, in later migrations too. A `SET LOCAL` holds
     * until its transaction ends, which is the end of its migration, overrides the session's value
     * until then, and does nothing outside a transaction, where PostgreSQL discards it. A zero, a
     * `DEFAULT` or a `RESET` takes the bound away again, since the role starts at zero. Measured on
     * PostgreSQL 18.4. A table created earlier in the run is left out, because nobody can hold a lock
     * on an object that did not exist a statement ago. Only `up()` runs at deploy time.
     *
     * @param  list<CapturedStatement>  $statements
     * @return array{?CapturedStatement, int}
     */
    private function lockWaitsIn(array $statements): array
    {
        $session = [];
        $local = [];
        $created = [];
        $first = null;
        $locking = 0;
        $previous = -1;

        foreach ($statements as $statement) {
            // A migration numbers its statements from zero, so the numbering starting again is where the
            // next migration, and the transaction it runs in, begins.
            if ($statement->sequence <= $previous) {
                $local = [];
            }

            $previous = $statement->sequence;

            if ($statement->direction !== MigrationDirection::Up || $statement->canonicalSql === null) {
                continue;
            }

            $set = $this->lockTimeoutSetIn($statement->canonicalSql);

            if ($set !== null) {
                if (! $set['local']) {
                    $session[$statement->connectionName] = $set['bounded'];
                    unset($local[$statement->connectionName]);
                } elseif ($statement->withinTransaction) {
                    $local[$statement->connectionName] = $set['bounded'];
                }

                continue;
            }

            $tables = array_values(array_filter(
                $statement->targets ?? [],
                static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table,
            ));

            if ($statement->statementKind === StatementKind::CreateTable) {
                foreach ($tables as $table) {
                    $created[$table->qualifiedName()] = true;
                }

                continue;
            }

            $digest = new MigrationStatementDigest($statement->sequence, $statement->statementKind, $statement->canonicalSql, $statement->withinTransaction, $statement->targets ?? []);

            if (! StrongLockStatements::takesStrongLock($digest)
                || ($tables !== [] && array_all($tables, static fn (StatementTarget $table): bool => isset($created[$table->qualifiedName()])))) {
                continue;
            }

            $locking++;

            if ($first === null && ! ($local[$statement->connectionName] ?? $session[$statement->connectionName] ?? false)) {
                $first = $statement;
            }
        }

        return [$first, $locking];
    }

    /**
     * What a statement does to its session's `lock_timeout`, or null when it leaves it alone.
     *
     * `local` says whether the change lasts only until the transaction ends, `bounded` whether the value
     * it leaves is one. A value that is not a duration this check can read is no bound it can count.
     *
     * @return array{local: bool, bounded: bool}|null
     */
    private function lockTimeoutSetIn(string $canonical): ?array
    {
        // The grammar refuses `RESET` and `DISCARD` today, so a migration holding one is not captured
        // whole and the verdict stops the deploy for that reason. Read here all the same, so the day
        // the grammar learns them they take the bound away instead of passing for none.
        if (preg_match('/^(?:RESET\s+(?:lock_timeout|ALL)|DISCARD\s+ALL)\s*;?\s*$/i', $canonical) === 1) {
            return ['local' => false, 'bounded' => false];
        }

        if (preg_match('/^SET\s+(?:(?<scope>SESSION|LOCAL)\s+)?lock_timeout\s*(?:=|\bTO\b)\s*(?<value>.+?)\s*;?\s*$/is', $canonical, $match) !== 1) {
            return null;
        }

        $value = preg_match("/^'((?:[^']|'')*)'$/s", $match['value'], $literal) === 1
            ? str_replace("''", "'", $literal[1])
            : $match['value'];

        return [
            'local' => strcasecmp($match['scope'], 'LOCAL') === 0,
            'bounded' => (DurationValue::milliseconds($value) ?? 0) > 0,
        ];
    }

    /** The tables a statement names, for a message: `orders`, or `orders` and `customers`. */
    private function tablesOf(CapturedStatement $statement): string
    {
        $names = array_map(
            static fn (StatementTarget $target): string => '`'.$target->qualifiedName().'`',
            array_values(array_filter(
                $statement->targets ?? [],
                static fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table,
            )),
        );

        return $names === [] ? 'a table' : implode(' and ', $names);
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
                documentationUrl: RuleDocumentationUrl::for(self::ID),
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
                documentationUrl: RuleDocumentationUrl::for(self::ID),
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
                documentationUrl: RuleDocumentationUrl::for(self::ID),
                context: $subject,
                severity: $verdict['severity'],
            ),
        };

        return $finding->withDowntimeClass($verdict['downtime'])->withConfidence($verdict['confidence']);
    }
}
