<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Catalog\Setting;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlServerSettingsReader;
use Pushery\SQLens\Drivers\Mysql\Rules\L3\Support\MetadataLockStatements;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\SqlModeFlags;
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
 * The MySQL half of context truth: the variables a migration is about to run under.
 *
 * The PostgreSQL sibling and this one answer the same question and share almost none of their
 * substance, which is why they are two classes rather than one with a `match`. The hazards differ,
 * the defaults differ, and the way each engine withholds a value differs.
 *
 * ## Which value each judgment reads: the one the migration runs under
 *
 * The question is what the migration's session runs with, and the answer is not the same variable
 * for every variable.
 *
 * - `sql_mode` is set per connection by Laravel, from the `strict` and `modes` keys of the
 *   connection's configuration, and left at the server's value when neither is set. The session this
 *   check reads through is opened from the migration connection's own configuration
 *   ({@see ReaderConnectionFactory::forPrimary()}), so Laravel set the same
 *   value on it, and SQLens does not touch `sql_mode`. So this one reads {@see Setting::$value}: a
 *   project with `strict => true` runs strict on a server that is not, and one with
 *   `strict => false` does not on a server that is.
 * - `lock_wait_timeout` is not set by Laravel, so a migration's session starts with the server's
 *   value, and SQLens bounds its OWN session, so the session value here is SQLens's and says nothing
 *   about the migration. This one reads {@see Setting::serverValue()}, and then the pending
 *   statements: a migration that sets its own bound before its first metadata lock, as
 *   `MY.L3.MISSING_LOCK_WAIT_TIMEOUT` asks, does not wait under the server's value.
 * - `foreign_key_checks` and `innodb_online_alter_log_max_size` read the server's value. Nothing
 *   sets the first per connection, and the second is global only.
 *
 * ## Why `performance_schema` being off is NOT undetermined here
 *
 * The reader falls back to `SHOW GLOBAL VARIABLES`, which answers on every server — so the VALUES
 * survive and only their PROVENANCE is lost. Reporting undetermined for the values would be a
 * different claim from the true one, and a louder one: it would say the timeouts are unknown when
 * they were read perfectly well.
 *
 * What IS reported is the loss of provenance, as its own finding. "Set in a config file" and "still
 * the compiled-in default" call for different actions, and a reading that cannot tell them apart has
 * to say so rather than let a missing source read as "nobody configured this".
 *
 * ## Only a `high` finding stops the deploy
 *
 * The same line as the PostgreSQL sibling, drawn by the same severities. The three `high` variables
 * each end badly on their own: a wait nothing ends, a foreign key that validates nothing, a column
 * narrow that truncates. The online-alter buffer at its default and the lost provenance are `medium`
 * and `info` — a default being reported and a note about the reading — so they travel with a passing
 * result as `pass` findings instead of stopping a deploy over nothing this check has measured.
 *
 * Every finding used to block here as well, and that included the provenance note: a server whose
 * `performance_schema` this role cannot read stopped every deploy with nothing but an `info` beside
 * it.
 *
 * ## With nothing pending, nothing is judged
 *
 * The same split the PostgreSQL sibling makes, and it matters more here. MySQL ships
 * `lock_wait_timeout` at one year, so every server left at its default reports an unbounded wait —
 * and without the split that `high` stopped every deploy, including the ones that carry no migration
 * at all. With nothing pending each variable is `not_applicable` with the reason `nothing_pending`,
 * named with its value and without the sentence about a change that is not happening.
 *
 * ## Reading it never changes it
 *
 * No `SET GLOBAL`, not even "just for this run".
 */
final readonly class ServerSettingsCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.CONTEXT.SETTING';

    /** The hour past which a lock wait is an outage, declared once for the lint rule and this check. */
    private const int LOCK_WAIT_CEILING_SECONDS = MetadataLockStatements::SESSION_WAIT_CEILING_SECONDS;

    /**
     * MySQL's shipped `innodb_online_alter_log_max_size`, in bytes (128 MiB).
     *
     * Judged against the default rather than against a computed need, with the same deliberate limit
     * on the claim the PostgreSQL sibling makes about `max_wal_size`: how much DML arrives during an
     * online ALTER depends on the traffic, which this check has not seen.
     *
     * @see https://dev.mysql.com/doc/refman/8.4/en/innodb-online-ddl-operations.html
     */
    private const int DEFAULT_ONLINE_ALTER_LOG_BYTES = 134_217_728;

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'mysql';
    }

    public function run(PreflightContext $context): CheckResult
    {
        // No try/catch here, and that is a measured decision rather than an oversight.
        // `MysqlServerSettingsReader` catches everything internally and answers with
        // `SettingsReading::failed()`, so a catch around this call is a branch nothing can
        // enter — the coverage gate found it unreachable, which is what unreachable code
        // looks like from the outside. A dead catch is worse than none: it reads as though
        // somebody checked, and it would silently start swallowing the day the reader's
        // contract changes.
        $reading = new MysqlServerSettingsReader($context->session)->read();

        if ($reading->failure instanceof UndeterminedReason) {
            return CheckResult::undetermined(
                self::ID,
                UndeterminedReason::SettingUnreadable,
                sprintf(
                    'the server variables could not be read (%s), so the conditions this migration '
                    .'will run under are unknown. That is not the same as them being fine.',
                    $reading->failure->value,
                ),
            );
        }

        $findings = [];
        $unreadable = [];

        // Whether anything is actually about to run, read ONCE, as the PostgreSQL sibling does: the
        // judgments argue from the same fact, and two readings of one fact is two chances for a report
        // to contradict itself.
        $pending = ! $context->pending->isEmpty();

        foreach ($this->judgments() as $name => $judge) {
            $setting = $reading->get($name);

            // MySQL withholds nothing per row for an ordinary account — the reading either answered
            // or did not — so a missing name here means this build is asking for a variable this
            // server does not have. Reported rather than shrugged off: a variable renamed across a
            // MySQL version would otherwise silently stop being judged.
            //
            // It is the only reason a variable here cannot be judged, which is a difference from the
            // PostgreSQL sibling rather than an omission. PostgreSQL masks `reset_val` for a role
            // without the privilege, so a present row with an absent value is an ordinary state there.
            // MySQL does not: the reader builds every `Setting` from the GLOBAL row it just read, so a
            // setting that exists has a value.
            if (! $setting instanceof Setting) {
                $unreadable[] = "`{$name}` is not among this server's variables, so it could not be judged";

                continue;
            }

            $finding = $judge($setting, $context, $pending);

            if ($finding instanceof Finding) {
                $findings[] = $finding;
            }
        }

        if (! $reading->carriesSources) {
            // Not undetermined, and the distinction is the point — see the class note. The values
            // were read; what was lost is where they came from.
            $findings[] = $this->finding(
                $context,
                $pending,
                'PROVENANCE_UNAVAILABLE',
                'performance_schema',
                'The variables above were read through `SHOW GLOBAL VARIABLES` rather than '
                .'`performance_schema`, because `performance_schema` is off or not granted to this '
                .'role. Their VALUES are correct; what is missing is where each came from. So a '
                .'value that looks deliberate here may simply be the compiled-in default nobody '
                .'ever set, and this report cannot tell you which.',
                // No premise: the note describes the reading, not the change, so there is nothing a
                // run with nothing pending would have to leave unsaid, and at `info` it is a pass.
                null,
                Severity::Info,
                DowntimeClass::Online,
            );
        }

        // Sorted by the outcome each finding already carries — `finding()` decided it once — so the
        // failures lead the report and each list keeps the order the findings arrived in.
        $blocking = [];
        $reported = [];

        foreach ($findings as $finding) {
            if ($finding->status->outcome === Outcome::Fail) {
                $blocking[] = $finding;
            } else {
                $reported[] = $finding;
            }
        }

        if ($unreadable !== []) {
            return CheckResult::undetermined(self::ID, UndeterminedReason::SettingUnreadable, implode('; ', $unreadable), [...$blocking, ...$reported]);
        }

        return $blocking === []
            ? CheckResult::pass(self::ID, $reported)
            : CheckResult::fail(self::ID, [...$blocking, ...$reported]);
    }

    /**
     * The variables this check judges, and what each verdict is.
     *
     * Each message comes in two halves, for the reason the PostgreSQL sibling gives: the first says
     * what the variable IS, the second what that means for the change about to run — and only the
     * second is true when a change is actually pending. A report that argues from "a migration is
     * about to run" beneath a header saying none was read teaches a reader to take the next real red
     * for noise.
     *
     * @return array<string, callable(Setting, PreflightContext, bool): ?Finding>
     */
    private function judgments(): array
    {
        return [
            'lock_wait_timeout' => fn (Setting $setting, PreflightContext $context, bool $pending): ?Finding => $this->lockWaitFinding((string) $setting->serverValue(), $context, $pending),
            'foreign_key_checks' => fn (Setting $setting, PreflightContext $context, bool $pending): ?Finding => $this->isOn((string) $setting->serverValue()) ? null : $this->finding(
                $context,
                $pending,
                'FOREIGN_KEY_CHECKS_OFF',
                'foreign_key_checks',
                'The server runs with `foreign_key_checks = OFF`. A migration that adds a foreign '
                .'key will be accepted and will validate nothing, so the constraint exists in the '
                .'schema and the data behind it was never checked. The failure surfaces later, as '
                .'rows that violate a constraint the database believes it is enforcing.',
                ' A migration is about to run under it.',
                Severity::High,
                DowntimeClass::Online,
            ),
            'sql_mode' => fn (Setting $setting, PreflightContext $context, bool $pending): ?Finding => $this->isStrict((string) $setting->value) ? null : $this->finding(
                $context,
                $pending,
                'SQL_MODE_NOT_STRICT',
                'sql_mode',
                sprintf(
                    'The connection the migrations run on has `sql_mode = \'%s\'`, which carries '
                    .'neither `STRICT_TRANS_TABLES` nor `STRICT_ALL_TABLES`. Laravel sets it per '
                    .'connection from the `strict` and `modes` keys of its configuration and leaves '
                    .'the server\'s value, `\'%s\'`, in place when neither is set. Outside strict mode '
                    .'a migration that narrows a column TRUNCATES the values that no longer fit and '
                    .'reports a warning rather than an error — so the migration succeeds, the deploy '
                    .'goes green, and the data is gone.',
                    (string) $setting->value,
                    (string) $setting->serverValue(),
                ),
                ' A migration is about to run under it.',
                Severity::High,
                DowntimeClass::Online,
            ),
            'innodb_online_alter_log_max_size' => fn (Setting $setting, PreflightContext $context, bool $pending): ?Finding => ! ctype_digit((string) $setting->serverValue()) || (int) $setting->serverValue() > self::DEFAULT_ONLINE_ALTER_LOG_BYTES ? null : $this->finding(
                $context,
                $pending,
                'ONLINE_ALTER_LOG_AT_DEFAULT',
                'innodb_online_alter_log_max_size',
                sprintf(
                    'The server is still on the shipped `innodb_online_alter_log_max_size` (%s '
                    .'bytes). An online ALTER buffers the DML that arrives while it runs; when the '
                    .'buffer fills, the ALTER FAILS — after doing most of its work, and under exactly '
                    .'the write load that made it fill. Nothing here has seen your traffic; this is the '
                    .'default being reported, not a computed need.',
                    $setting->serverValue(),
                ),
                ' A schema change is pending against it.',
                Severity::Medium,
                DowntimeClass::Online,
                Confidence::Heuristic,
            ),
        ];
    }

    /** MySQL answers a boolean variable as `ON`/`OFF` through SHOW and as `1`/`0` through the schema. */
    private function isOn(string $value): bool
    {
        return strtoupper($value) === 'ON' || $value === '1';
    }

    /** Whether a `sql_mode` value carries either strict flag. */
    private function isStrict(string $value): bool
    {
        $flags = SqlModeFlags::parse($value);

        return $flags->has('STRICT_TRANS_TABLES') || $flags->has('STRICT_ALL_TABLES');
    }

    /**
     * The verdict on `lock_wait_timeout`: the server's value, and whether the pending migrations run
     * under it.
     *
     * A migration's session starts with the server's value and stops waiting under it once the
     * migration sets its own. So the finding stops the deploy when a pending statement would wait
     * under the server's value, or when the statements handed over are not all the deploy runs and
     * nothing can say whether one would. Otherwise the value is still reported, as a note.
     */
    private function lockWaitFinding(string $value, PreflightContext $context, bool $pending): ?Finding
    {
        if (! ctype_digit($value) || (int) $value <= self::LOCK_WAIT_CEILING_SECONDS) {
            return null;
        }

        $state = sprintf(
            'The server runs with `lock_wait_timeout = %s` seconds. MySQL ships one year, '
            .'which at deploy time is the same thing as forever: a DDL blocked on a metadata '
            .'lock will sit there, and every statement that needs that table sits behind it. '
            .'Nothing here says a blocker exists — only that if one appears, nothing will end '
            .'the wait.',
            $value,
        );

        [$unbounded, $locking] = $this->lockWaitsIn($context->pending->statements);

        if ($unbounded instanceof CapturedStatement) {
            $premise = sprintf(
                ' A migration is about to run under it: a statement on %s takes a metadata lock before '
                .'its session sets a `lock_wait_timeout` of at most an hour.',
                $this->tablesOf($unbounded),
            );
        } elseif (! $context->pending->readInFull()) {
            $premise = ' A migration is about to run under it, and the statements handed to this check are '
                .'not all the deploy runs, so nothing here can say whether it sets its own bound first.';
        } else {
            return $this->finding(
                $context,
                $pending,
                'LOCK_WAIT_TIMEOUT_UNBOUNDED',
                'lock_wait_timeout',
                $state,
                $this->unwaitedPremise($locking),
                Severity::Info,
                DowntimeClass::Online,
            );
        }

        return $this->finding(
            $context,
            $pending,
            'LOCK_WAIT_TIMEOUT_UNBOUNDED',
            'lock_wait_timeout',
            $state,
            $premise,
            Severity::High,
            DowntimeClass::Blocking,
        );
    }

    /**
     * Why the pending migrations do not wait under the server's `lock_wait_timeout`: none of them
     * takes a metadata lock on a table that already exists, or each that does runs after its session
     * sets its own bound.
     */
    private function unwaitedPremise(int $locking): string
    {
        if ($locking === 0) {
            return ' No pending statement takes a metadata lock on a table that already exists, so '
                .'nothing in this deploy waits under it.';
        }

        return ' The pending migrations do not wait under it: each statement that takes a metadata '
            .'lock on a table that already exists runs after its session sets a '
            .'`lock_wait_timeout` of at most an hour.';
    }

    /**
     * The first pending statement that would wait under the server's `lock_wait_timeout`, and how many
     * statements take a metadata lock on a table that already exists.
     *
     * Read in the order the deploy runs them, and per connection: a `SET SESSION` bounds the session
     * that ran it and every later statement on it, the preamble `MY.L3.MISSING_LOCK_WAIT_TIMEOUT` asks
     * for. A table created earlier in the run is left out, since nobody can hold a lock on an object
     * that did not exist a statement ago. Only `up()` runs at deploy time.
     *
     * @param  list<CapturedStatement>  $statements
     * @return array{?CapturedStatement, int}
     */
    private function lockWaitsIn(array $statements): array
    {
        $bounded = [];
        $created = [];
        $first = null;
        $locking = 0;

        foreach ($statements as $index => $statement) {
            if ($statement->direction !== MigrationDirection::Up || $statement->canonicalSql === null) {
                continue;
            }

            // The same reading MY.L3.MISSING_LOCK_WAIT_TIMEOUT takes of the same statement, so the
            // preflight and the lint never answer one SET two ways.
            $setting = MetadataLockStatements::sessionTimeoutIn($statement->canonicalSql, 'lock_wait_timeout');

            if ($setting !== null) {
                $bounded[$statement->connectionName] = $setting['seconds'] !== null && $setting['seconds'] <= self::LOCK_WAIT_CEILING_SECONDS;

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

            $digest = new MigrationStatementDigest($index, $statement->statementKind, $statement->canonicalSql, $statement->withinTransaction, $statement->targets ?? []);

            if (! MetadataLockStatements::takesMetadataLock($digest)
                || ($tables !== [] && array_all($tables, static fn (StatementTarget $table): bool => isset($created[$table->qualifiedName()])))) {
                continue;
            }

            $locking++;

            if ($first === null && ! ($bounded[$statement->connectionName] ?? false)) {
                $first = $statement;
            }
        }

        return [$first, $locking];
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
     * One finding for a variable: a failure, a reported pass, or a not-applicable notice.
     *
     * Decided here and nowhere else. With nothing pending a variable is not applicable, whatever its
     * severity, and its message stops before the sentence about the change. With a migration pending,
     * `high` fails and everything below it is reported as a pass — see the class note for the line.
     *
     * A null premise marks a finding that argues from no change at all, and nothing pending leaves it
     * exactly as it is.
     */
    private function finding(
        PreflightContext $context,
        bool $pending,
        string $suffix,
        string $setting,
        string $state,
        ?string $premise,
        Severity $severity,
        DowntimeClass $downtimeClass,
        Confidence $confidence = Confidence::Deterministic,
    ): Finding {
        $ruleId = self::ID.'.'.$suffix;
        $location = Location::inCatalog($context->driver, $context->connection, $setting, SchemaObjectType::Setting);
        $subject = new SubjectContext(driver: $context->driver, profile: $context->profile, strictTools: false);

        $message = $state.($premise ?? '');

        $finding = match (true) {
            ! $pending && $premise !== null => Finding::notApplicable(
                ruleId: $ruleId,
                messagePrefix: DeployNotice::MESSAGE_PREFIX,
                message: $state,
                reason: NotApplicableReason::NothingPending,
                location: $location,
                category: Category::Safety,
                level: Level::Capturable,
                stability: StabilityTier::Stable,
                documentationUrl: RuleDocumentationUrl::for(self::ID),
                context: $subject,
                severity: $severity,
            ),
            $severity->isAtLeast(Severity::High) => Finding::fail(
                ruleId: $ruleId,
                messagePrefix: DeployNotice::MESSAGE_PREFIX,
                message: $message,
                location: $location,
                category: Category::Safety,
                level: Level::Capturable,
                stability: StabilityTier::Stable,
                documentationUrl: RuleDocumentationUrl::for(self::ID),
                context: $subject,
                severity: $severity,
            ),
            default => Finding::pass(
                ruleId: $ruleId,
                messagePrefix: DeployNotice::MESSAGE_PREFIX,
                message: $message,
                location: $location,
                category: Category::Safety,
                level: Level::Capturable,
                stability: StabilityTier::Stable,
                documentationUrl: RuleDocumentationUrl::for(self::ID),
                context: $subject,
                severity: $severity,
            ),
        };

        return $finding->withDowntimeClass($downtimeClass)->withConfidence($confidence);
    }
}
