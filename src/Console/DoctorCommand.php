<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\ConnectionProbe;
use Pushery\SQLens\Drivers\EffectiveConnectionConfig;
use Pushery\SQLens\Exceptions\InvalidGuardProfile;
use Pushery\SQLens\Guard\GuardProfile;
use Pushery\SQLens\PackageVersion;
use Pushery\SQLens\ServerVersion;
use Pushery\SQLens\Tools\ToolReport;
use Throwable;

/**
 * The one command the foundation already carries: `sqlens:doctor`. It claims the
 * `sqlens:` command namespace, proves the provider registers commands, and prints
 * the reproducibility parameters every reporter will later carry — the tool
 * versions and, per configured connection, the driver and the REAL server version.
 *
 * Three-valued and read-only: no write, no lock, and no query beyond a handshake (primum non
 * nocere). A version that cannot be had is reported as `undetermined` WITH a named reason — never
 * a silent "ok".
 *
 * By DEFAULT it opens nothing, and the reason it says so out loud is a measured one. Reading the
 * already-open handle is the right restraint for a lint run, but in a fresh CLI process nothing is
 * open — so every connection came back `undetermined`, `sqlite` included, and a healthy setup was
 * indistinguishable from a broken one in the output of the command that exists to tell them apart.
 * The default now names the switch that answers the question, and `--probe` opens a connection —
 * because a human running a diagnostic has asked for exactly that. It is SCOPED to the default
 * connection unless told otherwise, for a reason measured the same afternoon: one `DB_PORT` feeds
 * every entry in a stock `database.php`, so probing all of them points a MySQL driver at a
 * PostgreSQL port, where the TCP session establishes and the handshake never arrives.
 * The external tools are here too, and the line that matters about them is not "found" or "not
 * found" — it is what the reader LOSES. A diagnostic that reports an absence without naming its
 * cost invites a shrug, and the only reason to mention an optional tool at all is that its
 * absence is otherwise invisible.
 */
final class DoctorCommand extends Command
{
    /**
     * The two formats this command implements, and the only two it accepts.
     *
     * Its own pair rather than the reporter registry's four, deliberately: doctor reports the
     * ENVIRONMENT — tool versions, server versions — not findings, so there is no result for a
     * GitHub annotation or a SARIF log to describe. Routing it through the registry would make it
     * accept two formats it cannot produce, which is the same defect as hiding one it can.
     *
     * @var list<string>
     */
    private const array FORMATS = ['console', 'json'];

    /** @var string */
    protected $signature = 'sqlens:doctor
        {--format=console : The report format — console or json}
        {--probe=none : Open a connection to read its real server version — bare for the default connection, or a name, or `all`}
        {--strict : Answer the question a gate answers — would a strict-tools run fail on what is missing here?}';

    /** @var string */
    protected $description = 'Report the environment SQLens runs in: tool versions and each connection’s real server version.';

    public function handle(Repository $config, ServerVersion $versions, ToolReport $tools, ConnectionProbe $probe): int
    {
        $format = $this->option('format');

        // Resolved either way — constructing it connects to nothing — but handed on only for the
        // connections the operator actually asked about. A probe that were always passed would make
        // the connect the default, which is the one thing this command must not do.
        //
        // ⚠️ AND IT IS SCOPED, which is a correctness rule rather than a convenience. `DB_PORT` is
        // ONE variable and every connection in a stock `database.php` reads it, so a project
        // pointed at PostgreSQL hands the mariadb and mysql entries port 5432 as well. Opening
        // those is not a failed connect: the TCP session ESTABLISHES and the MySQL driver then
        // waits for a handshake packet a PostgreSQL server will never send. No timeout applies,
        // because nothing failed. Measured: `--probe` over all six connections printed the four
        // header lines and hung on the FIRST one, indefinitely, while the connection the operator
        // cared about sat two lines below, reachable.
        $probeScope = $this->probeScope($config);

        // Measured before this guard existed: `--format=yaml` printed the console report and exited
        // 0, and so did `--format=sarif` — which became a likely thing to type the day this package
        // learned SARIF. A pipeline handed console text where it asked for a machine format fails
        // somewhere else entirely, with nothing pointing back here.
        //
        // The rule is the package's own, stated in AuditCommand: an unknown format is a
        // misconfiguration with a clear message, never a quiet fall back to console.
        if (! is_string($format) || ! in_array($format, self::FORMATS, true)) {
            $this->output->getErrorStyle()->writeln(sprintf(
                'Unknown report format "%s". Available formats: %s.',
                is_scalar($format) ? (string) $format : get_debug_type($format),
                implode(', ', self::FORMATS),
            ));

            return ExitCode::Misconfiguration->value;
        }

        if ($format === 'json') {
            $this->line((string) json_encode($this->payload($config, $versions, $tools, $probe, $probeScope), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return $this->strictVerdict($tools);
        }

        // Reproducibility parameters, in a fixed order so two runs on the same state
        // print byte-identically.
        $this->line('php: '.PHP_VERSION);
        $this->line('laravel: '.$this->getLaravel()->version());
        $this->line('sqlens: '.$this->packageVersion());
        $this->line('os: '.PHP_OS_FAMILY);

        /** @var array<string, mixed> $connections */
        $connections = $config->get('database.connections', []);
        $names = array_keys($connections);
        sort($names, SORT_STRING);

        foreach ($names as $name) {
            // Through the parser, not out of the array: a `url`-only connection names its driver
            // in the URL scheme and carries no `driver` key at all, so reading the key printed
            // `driver=unknown` for a configuration Laravel and `sqlens:lint` both accept — from the
            // command whose whole job is telling an operator what SQLens sees.
            $driver = EffectiveConnectionConfig::driverFor($config->get("database.connections.{$name}")) ?? 'unknown';
            $this->line(sprintf('connection %s: driver=%s server=%s', $name, $driver, $this->serverVersion($versions, $probe, $probeScope, $name)));
        }

        foreach ($tools->entries() as $tool) {
            $this->line($tool['available']
                ? sprintf('tool %s: %s (%s)', $tool['name'], $tool['version'] ?? 'version unreported', $tool['resolution'])
                // The cost, named. "not installed" is a fact; "17 checks nobody is running" is a
                // decision somebody has to make on purpose.
                : sprintf(
                    'tool %s: %s — %d check(s) nobody is running. It would add: %s',
                    $tool['name'],
                    $tool['resolution'],
                    $tool['missing_checks'],
                    $tool['adds'],
                ));
        }

        $this->strictAdvice($tools);

        // Diagnosis is never a gate — BY DEFAULT, and the qualification is the whole of `--strict`.
        // `doctor` says what SQLens sees; deciding what to do about it is the reader's, and a
        // command that failed for reporting would stop being run.
        //
        // Asking is a different act from reporting. `--strict` is somebody putting the gate's own
        // question to the machine in front of them, and answering it with an exit code is the only
        // form a pipeline can read.
        return $this->strictVerdict($tools);
    }

    /**
     * The tools that are not usable right now, by the report's own definition of usable.
     *
     * Derived from `available` rather than re-decided here. A second rule for "would this break a
     * strict run" would be free to disagree with the one the runners apply, and it would disagree
     * exactly where it matters — on the machine where a person is trying to find out why the gate
     * failed and their laptop did not.
     *
     * @return list<string>
     */
    private function unusableTools(ToolReport $tools): array
    {
        return array_values(array_map(
            static fn (array $tool): string => $tool['name'],
            array_filter($tools->entries(), static fn (array $tool): bool => $tool['available'] === false),
        ));
    }

    /**
     * Under `--strict`, name the tools a strict-tools run would fail on — or say plainly that none would.
     *
     * Both halves are printed, and the second is not politeness: a command that says nothing when
     * everything is fine is one whose silence a reader has to interpret, and the interpretation
     * ("it did not check") is available at exactly the wrong moment.
     */
    private function strictAdvice(ToolReport $tools): void
    {
        if ($this->option('strict') !== true) {
            return;
        }

        $unusable = $this->unusableTools($tools);

        $this->line($unusable === []
            ? 'strict: every known tool is usable here — a strict-tools run would not fail on this machine'
            : sprintf(
                'strict: a strict-tools run would FAIL on this machine, on %s. That is the difference between here and the gate.',
                implode(', ', $unusable),
            ));
    }

    /**
     * The exit code, which is `0` unless `--strict` was asked for and something is missing.
     *
     * `UndeterminedInStrictMode` rather than a code of its own: a missing tool is a check that could
     * not run, and strict mode is the project's decision to treat that as a failure. Giving it a
     * fifth code would make a pipeline learn a new number for a state it already handles.
     */
    private function strictVerdict(ToolReport $tools): int
    {
        if ($this->option('strict') !== true) {
            return self::SUCCESS;
        }

        return $this->unusableTools($tools) === []
            ? self::SUCCESS
            : ExitCode::UndeterminedInStrictMode->value;
    }

    /**
     * The same facts as a stable, sorted structure.
     *
     * Schema-stable and deterministic on purpose: the JSON form exists so a pipeline can assert
     * on it, and a shape that varied with iteration order would make that assertion a coin toss.
     *
     * @param  list<string>  $probeScope  the connections this run may open
     * @return array<string, mixed>
     */
    private function payload(Repository $config, ServerVersion $versions, ToolReport $tools, ConnectionProbe $probe, array $probeScope): array
    {
        /** @var array<string, mixed> $connections */
        $connections = $config->get('database.connections', []);
        $names = array_keys($connections);
        sort($names, SORT_STRING);

        return [
            'php' => PHP_VERSION,
            'laravel' => $this->getLaravel()->version(),
            'sqlens' => $this->packageVersion(),
            'os' => PHP_OS_FAMILY,
            'connections' => array_map(fn (string $name): array => [
                'name' => $name,
                'driver' => EffectiveConnectionConfig::driverFor($config->get("database.connections.{$name}")) ?? 'unknown',
                'server' => $this->serverVersion($versions, $probe, $probeScope, $name),
            ], $names),
            'tools' => $tools->entries(),
            'guard' => $this->guardSection($config, $names),
        ];
    }

    /**
     * What the runtime guard is doing, said out loud — including when it is doing nothing.
     *
     * ## Why `off` is a value and not an absence
     *
     * A deactivated guard that does not appear in this output reads exactly like an active one. The
     * whole purpose of a diagnostic is telling a healthy environment from a broken one, and a field
     * that is present only when things are on answers that question with silence in the case where
     * somebody most needs an answer.
     *
     * ## The `undetermined` case is a real state, not a formatting branch
     *
     * A profile can be set, valid, armed — and still watching nothing, because it names connections
     * this application does not use at runtime. That is not `off` and it is not fine: it is a
     * guardrail somebody configured and will never hear from. Reported with its reason named, the
     * same three-valued discipline every check in this package follows.
     *
     * @param  list<string>  $connections  every connection this application defines
     * @return array<string, mixed>
     */
    private function guardSection(Repository $config, array $connections): array
    {
        $named = $config->get('sqlens.guard.profile');

        /** @var array<string, mixed> $guard */
        $guard = is_array($declared = $config->get('sqlens.guard')) ? $declared : [];

        // ONE gate, and it is the resolver's. An `if (! is_string($named) || $named === '')` stood
        // here first and did two things wrong at once: it made the resolver's own null unreachable
        // from this method — a branch no test can enter — and it answered `off` / `pass` for
        // `profile: ''`, which the resolver treats as a misconfiguration. An empty profile name is
        // not a guardrail that is off, it is one somebody meant to name and did not, and the command
        // whose whole job is finding that would have said everything was fine.
        try {
            $profile = GuardProfile::resolve($guard);
        } catch (InvalidGuardProfile $refusal) {
            // Reported rather than thrown, and only HERE. Everywhere else this exception ends the
            // boot, which is right — but the one command whose job is diagnosing a broken setup must
            // survive long enough to describe it.
            return [
                // The name as WRITTEN when it is one at all, and the type otherwise: `profile: true`
                // has no name to echo, and printing an empty string there tells the reader nothing
                // about what they typed.
                'profile' => is_string($named) && $named !== '' ? $named : get_debug_type($named),
                'status' => 'fail',
                'reason' => $refusal->getMessage(),
                'guardrails' => [],
                'channel' => null,
            ];
        }

        // Nothing named at all: every guardrail is off, which is the shipped default.
        if (! $profile instanceof GuardProfile) {
            return ['profile' => 'off', 'status' => 'pass', 'guardrails' => [], 'channel' => null];
        }

        $armed = array_keys(array_filter([
            'lazy_loading' => $profile->lazyLoading,
            'discarding_attributes' => $profile->discardingAttributes,
            'missing_attributes' => $profile->missingAttributes,
            'destructive_commands' => $profile->destructiveCommands,
            'slow_query' => $profile->slowQueryEnabled,
            'runtime_ddl' => $profile->runtimeDdl,
            'unbound_raw_sql' => $profile->unboundRawSql,
        ]));

        $unused = array_values(array_diff($profile->connections, $connections));

        return [
            'profile' => $profile->name,
            // Undetermined, with the reason named. A profile watching a connection nothing defines
            // is armed and deaf, which is neither on nor off.
            'status' => $unused === [] ? ($armed === [] ? 'undetermined' : 'pass') : 'undetermined',
            ...($unused !== [] ? ['reason' => 'guard_watches_unused_connection: the profile names '
                .implode(', ', $unused).', which this application does not define — the guardrails '
                .'are armed and will never see a query'] : []),
            ...($unused === [] && $armed === [] ? ['reason' => 'guard_profile_arms_nothing: the '
                .'profile resolves and every guardrail in it is false, so naming it changes '
                .'nothing'] : []),
            'guardrails' => $armed,
            'channel' => $profile->logChannel,
            'throws' => $profile->throw,
        ];
    }

    /**
     * The banner comes from the ONE acquisition unit, never from a second read of
     * the same server. It used to call getPdo() here, which resolves the lazy
     * connection closure — that is a CONNECT, and opening a production database
     * just to print its version is exactly the harm this package promises not to
     * do. ServerVersion reads the handle that is already open, or says it cannot.
     *
     * ── and the default alone was not enough, measured ───────────────────────────────────────
     * In a fresh CLI child with correct credentials and a reachable PostgreSQL 18, EVERY
     * connection reported undetermined — `sqlite` included, which needs no server at all. Nothing
     * had connected, so there was no handle, so there was no version: a healthy environment
     * printing the same line as a broken one, from the command whose only job is telling them
     * apart. The default keeps its restraint and now says WHY, naming the switch that answers it;
     * `--probe` opens the connection, because a human asking a diagnostic to go and look is a
     * different act from a lint run touching a database nobody pointed it at.
     *
     * @param  list<string>  $probeScope  the connections this run may open
     */
    private function serverVersion(ServerVersion $versions, ConnectionProbe $probe, array $probeScope, string $name): string
    {
        try {
            if (in_array($name, $probeScope, true)) {
                return $probe->banner($name) ?? 'undetermined (the connection opened and reported no server version)';
            }

            return $versions->resolve($name) ?? 'undetermined (no connection is open — pass --probe to open one)';
        } catch (Throwable) {
            // The exception TYPE, never its message. A PDO connect error routinely
            // reads "connection to server at \"10.0.0.1\", port 5432 failed: FATAL:
            // password authentication failed for user \"deployer\"" — host, port and
            // username, printed by a diagnostic command people paste into issues.
            return in_array($name, $probeScope, true)
                ? 'undetermined (the connection could not be opened)'
                : 'undetermined (the connection could not be inspected)';
        }
    }

    /**
     * Which connections this run is allowed to OPEN — empty for none, which is the default.
     *
     * The option carries the string `none` as its default rather than null, and that is what makes
     * the bare `--probe` expressible at all: an optional-value option hands back null both when it
     * is absent and when it is passed without a value, so a null default would make "do not probe"
     * and "probe the default connection" the same input.
     *
     * @return list<string>
     */
    private function probeScope(Repository $config): array
    {
        $probe = $this->option('probe');

        if ($probe === 'none') {
            return [];
        }

        // `--probe` with no value: the connection this application actually uses. That is the
        // question a diagnostic is nearly always being asked, and it is the only scope that cannot
        // wander into an entry nobody configured on purpose.
        if ($probe === null || $probe === '') {
            $default = $config->get('database.default');

            return is_string($default) ? [$default] : [];
        }

        if ($probe !== 'all') {
            return [(string) $probe];
        }

        /** @var array<string, mixed> $connections */
        $connections = $config->get('database.connections', []);

        // `--probe=all` is a deliberate choice with a known hazard, spelled out at the call site:
        // an entry inheriting a port from another engine can block on a handshake that never comes.
        // It stays available because a full sweep is genuinely useful on a machine where every
        // connection IS configured — it just must never be what someone gets by accident.
        return array_map(strval(...), array_keys($connections));
    }

    private function packageVersion(): string
    {
        return PackageVersion::current();
    }
}
