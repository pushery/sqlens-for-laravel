<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Pushery\SQLens\Catalog\Setting;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\DeployNotice;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Drivers\Mysql\Catalog\MysqlServerSettingsReader;
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
 * The MySQL half of context truth: the variables a migration is about to run under.
 *
 * The PostgreSQL sibling and this one answer the same question and share almost none of their
 * substance, which is why they are two classes rather than one with a `match`. The hazards differ,
 * the defaults differ, and the way each engine withholds a value differs.
 *
 * ## Why it reads the GLOBAL value and not the session's
 *
 * Laravel sets `sql_mode` and the time zone per connection, and SQLens bounds its own session on top
 * of that. So the value in effect for this connection routinely differs from the server's, and a
 * check reading the session value would report the framework's choice back to the project as its
 * server configuration. Every judgment here reads {@see Setting::serverValue()}, which on MySQL is
 * the `GLOBAL` row.
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
 * ## Reading it never changes it
 *
 * No `SET GLOBAL`, not even "just for this run".
 */
final readonly class ServerSettingsCheck implements PreflightCheck
{
    public const string ID = 'DEPLOY.CONTEXT.SETTING';

    /**
     * How long a lock wait stops being a wait and becomes an outage, in seconds.
     *
     * A DECLARED expectation rather than a measured one, and it is declared here so it is arguable.
     * MySQL ships `lock_wait_timeout = 31536000` — one year — which at deploy time is
     * indistinguishable from waiting forever. An hour is the line: past it, the deploy has already
     * failed in every way that matters to whoever is watching it, and the metadata lock it is
     * holding has been blocking every DDL behind it for that entire time.
     *
     * @see https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html
     */
    private const int LOCK_WAIT_CEILING_SECONDS = 3600;

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
                sprintf(
                    'the server variables could not be read (%s), so the conditions this migration '
                    .'will run under are unknown. That is not the same as them being fine.',
                    $reading->failure->value,
                ),
            );
        }

        $findings = [];
        $unreadable = [];

        foreach ($this->judgments() as $name => $judge) {
            $setting = $reading->get($name);

            $reason = $this->unreadableReason($name, $setting);

            if ($reason !== null) {
                $unreadable[] = $reason;

                continue;
            }

            $finding = $judge((string) $setting?->serverValue(), $context);

            if ($finding instanceof Finding) {
                $findings[] = $finding;
            }
        }

        if (! $reading->carriesSources) {
            // Not undetermined, and the distinction is the point — see the class note. The values
            // were read; what was lost is where they came from.
            $findings[] = $this->finding(
                $context,
                'PROVENANCE_UNAVAILABLE',
                'performance_schema',
                'The variables above were read through `SHOW GLOBAL VARIABLES` rather than '
                .'`performance_schema`, because `performance_schema` is off or not granted to this '
                .'role. Their VALUES are correct; what is missing is where each came from. So a '
                .'value that looks deliberate here may simply be the compiled-in default nobody '
                .'ever set, and this report cannot tell you which.',
                Severity::Info,
                DowntimeClass::Online,
            );
        }

        if ($unreadable !== []) {
            return CheckResult::undetermined(self::ID, 'setting_unreadable: '.implode('; ', $unreadable), $findings);
        }

        return $findings === []
            ? CheckResult::pass(self::ID)
            : CheckResult::fail(self::ID, $findings);
    }

    /** Why this variable could not be judged, or null when it can be. */
    private function unreadableReason(string $name, ?Setting $setting): ?string
    {
        if (! $setting instanceof Setting) {
            // MySQL withholds nothing per row for an ordinary account — the reading either answered
            // or did not — so a missing name here means this build is asking for a variable this
            // server does not have. Reported rather than shrugged off: a variable renamed across a
            // MySQL version would otherwise silently stop being judged.
            return "`{$name}` is not among this server's variables, so it could not be judged";
        }

        // No null-value branch here, and that is a difference from the PostgreSQL sibling rather
        // than an omission. PostgreSQL MASKS `reset_val` for a role without the privilege, so a
        // present row with an absent value is an ordinary state there. MySQL does not: the reader
        // builds every `Setting` from the GLOBAL row it just read, so a setting that exists has a
        // value. The coverage gate found the branch unreachable, which is what that difference looks
        // like from the outside.
        return null;
    }

    /**
     * The variables this check judges, and what each verdict is.
     *
     * @return array<string, callable(string, PreflightContext): ?Finding>
     */
    private function judgments(): array
    {
        return [
            'lock_wait_timeout' => fn (string $value, PreflightContext $context): ?Finding => ! ctype_digit($value) || (int) $value <= self::LOCK_WAIT_CEILING_SECONDS ? null : $this->finding(
                $context,
                'LOCK_WAIT_TIMEOUT_UNBOUNDED',
                'lock_wait_timeout',
                sprintf(
                    'The server runs with `lock_wait_timeout = %s` seconds, and a migration is about '
                    .'to run. MySQL ships one year, which at deploy time is the same thing as '
                    .'forever: a DDL blocked on a metadata lock will sit there, and every statement '
                    .'that needs that table sits behind it. Nothing here says a blocker exists — '
                    .'only that if one appears, nothing will end the wait.',
                    $value,
                ),
                Severity::High,
                DowntimeClass::Blocking,
            ),
            'foreign_key_checks' => fn (string $value, PreflightContext $context): ?Finding => $this->isOn($value) ? null : $this->finding(
                $context,
                'FOREIGN_KEY_CHECKS_OFF',
                'foreign_key_checks',
                'The server runs with `foreign_key_checks = OFF`. A migration that adds a foreign '
                .'key will be accepted and will validate nothing, so the constraint exists in the '
                .'schema and the data behind it was never checked. The failure surfaces later, as '
                .'rows that violate a constraint the database believes it is enforcing.',
                Severity::High,
                DowntimeClass::Online,
            ),
            'sql_mode' => fn (string $value, PreflightContext $context): ?Finding => str_contains($value, 'STRICT_TRANS_TABLES') || str_contains($value, 'STRICT_ALL_TABLES') ? null : $this->finding(
                $context,
                'SQL_MODE_NOT_STRICT',
                'sql_mode',
                'The server\'s `sql_mode` carries neither `STRICT_TRANS_TABLES` nor '
                .'`STRICT_ALL_TABLES`. Outside strict mode a column narrowed by this migration '
                .'TRUNCATES the values that no longer fit and reports a warning rather than an '
                .'error — so the migration succeeds, the deploy goes green, and the data is gone.',
                Severity::High,
                DowntimeClass::Online,
            ),
            'innodb_online_alter_log_max_size' => fn (string $value, PreflightContext $context): ?Finding => ! ctype_digit($value) || (int) $value > self::DEFAULT_ONLINE_ALTER_LOG_BYTES ? null : $this->finding(
                $context,
                'ONLINE_ALTER_LOG_AT_DEFAULT',
                'innodb_online_alter_log_max_size',
                sprintf(
                    'The server is still on the shipped `innodb_online_alter_log_max_size` (%s '
                    .'bytes) while a schema change is pending. An online ALTER buffers the DML that '
                    .'arrives while it runs; when the buffer fills, the ALTER FAILS — after doing '
                    .'most of its work, and under exactly the write load that made it fill. Nothing '
                    .'here has seen your traffic; this is the default being reported, not a '
                    .'computed need.',
                    $value,
                ),
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
