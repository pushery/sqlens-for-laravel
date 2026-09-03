<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * One server variable as an audit sees it — the value, and everything needed to know what it means.
 *
 * A bare name and value is not enough to judge a server on, and every field here exists because
 * leaving it out produces a specific wrong answer:
 *
 * - **Scope.** A `session` value is this connection's, not the server's. Reporting one as a global
 *   would tell a project its production default is wrong when only the audit's own session was —
 *   and behind a transaction pooler a session value may not even be ours (measured: one client's
 *   `SET` lands on another's connection).
 * - **Source.** "Set in the config file" and "still the compiled-in default" call for different
 *   actions, and a finding that could not tell them apart would send half its readers to the wrong
 *   file.
 * - **Pending restart.** A value already changed on disk but not yet live looks correct to anyone
 *   reading the config and wrong to the running server. Which of the two an audit reports decides
 *   whether it is describing the database people have or the one they will have.
 */
final readonly class Setting
{
    private function __construct(
        public string $name,
        /**
         * The value in effect for the READING SESSION, or null when the server withheld it.
         *
         * PostgreSQL withholds exactly this way for superuser-restricted settings: the `pg_settings`
         * row is there, `setting` is NULL, and nothing raises. Reading that as an empty string would
         * turn "you may not see this" into "it is not set" — the same sentence with the opposite
         * meaning, and the one that sends a reader to change a value they cannot even read.
         *
         * **This is the session's value, not the server's**, and a rule about the server's
         * configuration wants {@see self::serverValue()} instead. The distinction is not pedantry:
         * Laravel sets `sql_mode` and the timezone on every MySQL connection from the connection
         * config, and SQLens bounds its own session's timeouts, so for those names this field
         * describes the audit rather than the database.
         */
        public ?string $value,
        public SettingScope $scope,
        public ?string $source,
        /**
         * Whether the running value is waiting for a restart to catch up with the configured one.
         *
         * Null means the engine does not report it — not "no". MySQL has no equivalent of
         * PostgreSQL's `pending_restart`, and answering `false` there would claim a check nobody
         * performed.
         */
        public ?bool $pendingRestart = null,
        /**
         * What the server would use if nobody had set this — and what a fresh session would see.
         *
         * These two are what let a rule tell the SERVER's configuration from the audit's own. The
         * reading session sets a few bounds of its own — `statement_timeout`, `lock_timeout`, the
         * read-only seal — so for those names the effective value describes SQLens rather than the
         * database. Without a baseline to compare against, that limitation is unresolvable and a
         * rule about a timeout would be reporting our own session back to the project as its
         * production configuration.
         *
         * Null on an engine that does not report them; MySQL does not.
         */
        public ?string $bootValue = null,
        public ?string $resetValue = null,
        /**
         * The unit the value is counted in — `ms`, `kB`, `8kB` — or null when it is unitless.
         *
         * A rule comparing `statement_timeout` against "five seconds" has to know whether it is
         * holding `5000` or `5s`, and PostgreSQL reports the bare number with the unit beside it.
         * Comparing without it is how a check passes on a value a thousand times too small.
         */
        public ?string $unit = null,
        /**
         * Which file the value came from, when the server will say.
         *
         * The difference between a finding a reader can act on and one they have to go hunting for.
         * Null is ordinary rather than exceptional: it is superuser-restricted, so on a managed
         * database it is normally absent.
         */
        public ?string $sourceFile = null,
        /**
         * What it takes to change this — `postmaster` needs a restart, `user` does not.
         *
         * A remediation that says "set this" without saying "and restart" is advice somebody will
         * follow and then wonder why nothing changed.
         */
        public ?string $context = null,
        /**
         * What the SERVER is configured to, independent of what this session is running with.
         *
         * The one field a server-baseline rule may judge, and the reason it exists as its own name
         * rather than as a convention about which of the other fields to read.
         *
         * The two engines answer this from opposite columns — PostgreSQL from `pg_settings.reset_val`
         * (`setting` is the session's), MySQL from `performance_schema.global_variables` (its session
         * view is the per-connection one). A rule reaching for "the value" would therefore be right
         * on one engine and silently wrong on the other, and wrong in the worst direction: it would
         * report the audit's own connection settings back to the project as its production
         * configuration. Naming the field is what makes that impossible to get wrong; a docblock
         * saying "use reset_val on PostgreSQL" is a rule seventeen rule authors have to remember.
         *
         * Null means the reading could not establish it — never a default to fall back on. A rule
         * that finds null reports `undetermined` with a reason, because judging a server against a
         * compiled-in default while believing it read the configuration is precisely a silent green.
         */
        public ?string $serverValue = null,
    ) {}

    public static function of(
        string $name,
        ?string $value,
        SettingScope $scope,
        ?string $source = null,
        ?bool $pendingRestart = null,
        ?string $bootValue = null,
        ?string $resetValue = null,
        ?string $unit = null,
        ?string $sourceFile = null,
        ?string $context = null,
        ?string $serverValue = null,
    ): self {
        return new self($name, $value, $scope, $source, $pendingRestart, $bootValue, $resetValue, $unit, $sourceFile, $context, $serverValue);
    }

    /**
     * What the server is configured to, or null when the reading could not establish it.
     *
     * An accessor rather than bare field access so the "null is undetermined, never a default"
     * contract has one place to be stated and one place to be found.
     */
    public function serverValue(): ?string
    {
        return $this->serverValue;
    }

    /** Whether changing this value needs the server restarted before it takes effect. */
    public function needsRestartToChange(): ?bool
    {
        return $this->context === null ? null : $this->context === 'postmaster';
    }

    /**
     * Whether this value is the one the reading session installed, rather than the server's.
     *
     * True when the effective value differs from what a fresh session would get. That is the test a
     * rule about `statement_timeout` or `lock_timeout` has to make before believing what it reads:
     * SQLens bounds its own session on purpose, and a rule that skipped this check would report the
     * audit's own hygiene as the database's configuration.
     *
     * Null when the engine reports no baseline to compare against — unknown, not "no".
     *
     * Compared against {@see self::$serverValue} rather than `resetValue`, so the question is asked
     * the same way on both engines: is what this session is running with the same as what the server
     * is configured to? `resetValue` is a PostgreSQL detail column and MySQL has no counterpart, so
     * reading it here would answer "unknown" on MySQL for a fact it can state plainly.
     */
    public function overriddenInThisSession(): ?bool
    {
        return $this->serverValue === null || $this->value === null
            ? null
            : $this->value !== $this->serverValue;
    }

    /** Whether the server actually told us what this is set to. */
    public function isReadable(): bool
    {
        return $this->value !== null;
    }

    /**
     * Whether this value describes the SERVER rather than the reading session.
     *
     * The question every server-baseline rule has to ask first. A rule that judged a session value
     * as if it were the server's would report the audit's own connection back to the project as
     * its production configuration.
     */
    public function describesTheServer(): bool
    {
        return $this->scope === SettingScope::Global;
    }

    /** A stable rendering, so two readings diff cleanly. */
    public function describe(): string
    {
        return sprintf(
            '%s = %s (%s%s%s)',
            $this->name,
            match (true) {
                $this->value === null => '(withheld)',
                $this->value === '' => "''",
                default => $this->value,
            },
            $this->scope->value.($this->unit === null ? '' : ' '.$this->unit),
            $this->source === null ? '' : ', from '.$this->source,
            $this->pendingRestart === true ? ', pending restart' : '',
        );
    }
}
