<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Audit\ServerLifetime;
use Pushery\SQLens\Contracts\JudgesTheServerItRunsOn;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Security\OriginBinding;
use Pushery\SQLens\Security\PathBinding;

/**
 * The immutable context every subject carries, so a rule never reaches for
 * global config or a facade — everything it needs is injected. That is what
 * lets the fast path run with no database connection.
 *
 * The server version is nullable: it may be the real detected version, a pinned
 * assume_server_version, or genuinely unknown. A rule that needs a version and
 * finds none yields an undetermined finding, never a guess.
 *
 * It is carried as the run's whole {@see ResolvedServerVersion} rather than as a bare
 * version, because a rule that consults a version-windowed DATA SOURCE — the MySQL
 * online-DDL matrix is the one — needs the run's own reason for having no version, not a
 * second reason invented at the point of use. {@see self::$serverVersion} is derived from
 * it and stays the accessor almost every reader wants: one fact, two shapes, never two
 * facts that can disagree.
 */
final readonly class SubjectContext
{
    /**
     * The version itself, derived from the run's resolution.
     *
     * A rule that only needs to know WHICH version reads this and nothing else — it
     * carries no version SOURCE, so a pin and a live read of the same version are
     * literally the same value here. That is the determinism the pin exists to guarantee,
     * and it holds by construction rather than by discipline.
     */
    public ?ServerVersion $serverVersion;

    public function __construct(
        public string $driver,
        public string $profile,
        public bool $strictTools,
        public ?ResolvedServerVersion $resolvedServerVersion = null,
        /**
         * The connection this subject came from, when it came from one.
         *
         * A catalog finding has to name the instance it is about — on any project with more than
         * one database, "a foreign key is unindexed" is unactionable without it. Nullable because
         * a migration read from disk genuinely has no connection, and inventing one there would be
         * worse than leaving it out. Never a DSN or a password: the connection NAME.
         */
        public ?string $connection = null,
        /**
         * Whether the instance this subject was read from accepts writes.
         *
         * `primary`, `replica`, `undetermined` — or null when the question does not arise, which
         * is the ordinary case for a migration read off disk. The distinction matters because it
         * is not a decoration on the finding, it is part of what the finding MEANS: a settings
         * value that is wrong on the primary is a production problem, while the same value on a
         * replica describes a machine that serves no writes and may be sized that way on purpose.
         * A reader without it has to guess, and the safe guess is the pessimistic one.
         *
         * A string rather than the audit's enum, because this class is the driver-neutral core
         * every rule sees, and the enum lives in the audit suite. The audit stamps the value; the
         * core carries it.
         */
        public ?string $instanceRole = null,
        /**
         * How this run decides whether a file is a migration — the registered paths, resolved once.
         *
         * A RUN fact, not a rule fact, and that is why it travels here rather than arriving through
         * a rule's constructor. The paths are `databasePath('migrations')` plus everything a package
         * registered on the migrator, and the lint layer already resolves them once at the top of a
         * run. A rule resolving them again would be a second answer that can disagree with the first
         * — and a rule hard-coding `database/migrations` would be exactly the heuristic the binding
         * exists to replace: it misses a package path, misses a tenant subdirectory, and calls a
         * seeder named like a migration a migration.
         *
         * Null when the run never established them — a catalog subject read off a live server has no
         * file behind it at all. A path-bound rule reads that as
         * {@see OriginBinding::Unknown} and answers `undetermined`, which
         * is the honest answer rather than a silent pass.
         */
        public ?PathBinding $pathBinding = null,
        /**
         * Whether the server this run read from outlives the run — `persistent` or `disposable`.
         *
         * A RUN fact for the same reason `instanceRole` above is one, and a string for the same
         * reason too: the enum lives in the audit suite, and this class is the driver-neutral core
         * every rule sees. The audit stamps the value; the core carries it.
         *
         * It changes what a SERVER finding means, not whether one is reported. A pipeline's database
         * is a container the job creates and destroys, so its authentication file, its transport
         * security and the attributes of its connection role describe a fixture — while the identical
         * facts on a host somebody operates are among the most serious things this package reports.
         * Which rules that applies to is declared by the rules themselves, through
         * {@see JudgesTheServerItRunsOn}; everything about the schema is
         * judged here exactly as it would be anywhere.
         *
         * Never null and never undetermined, unlike the role beside it: there is no cheap fact that
         * tells a container from a production server — both answer every query identically — so this
         * is DECLARED, and an absent declaration is `persistent`. That direction is the only safe
         * one: reading silence as "probably a container" would turn the strictest checks in the
         * package off for every project that never heard of the key.
         */
        public string $serverLifetime = ServerLifetime::Persistent->value,
    ) {
        $this->serverVersion = $resolvedServerVersion?->version;
    }

    /**
     * The same context carrying the run's resolved server version — a real detected one,
     * an assume_server_version pin, or a named "could not determine", alike.
     *
     * The whole resolution travels, but what a rule branches on stays the version: the
     * source rides along only so a version-windowed data source can report the run's OWN
     * reason when there is no version to look one up with.
     */
    public function withResolvedServerVersion(?ResolvedServerVersion $resolvedServerVersion): self
    {
        return new self($this->driver, $this->profile, $this->strictTools, $resolvedServerVersion, $this->connection, $this->instanceRole, $this->pathBinding, $this->serverLifetime);
    }

    /**
     * The same context, naming the connection the subject was read from.
     *
     * Stamped by the catalog reader rather than by each caller: the reader is handed a session, the
     * session knows its own connection, and a rule sees neither — so the one place that can get it
     * right is the one place that has both.
     */
    public function withConnection(string $connection): self
    {
        return new self($this->driver, $this->profile, $this->strictTools, $this->resolvedServerVersion, $connection, $this->instanceRole, $this->pathBinding, $this->serverLifetime);
    }

    /**
     * The same context, naming the role of the instance the subject came from.
     *
     * Stamped once by the audit runner, for the same reason the connection is stamped by the
     * reader: it is the one place that has both the target and the context, and a rule sees
     * neither.
     */
    public function withInstanceRole(?string $instanceRole): self
    {
        return new self($this->driver, $this->profile, $this->strictTools, $this->resolvedServerVersion, $this->connection, $instanceRole, $this->pathBinding, $this->serverLifetime);
    }

    /**
     * The same context, carrying the run's OWN profile and strict-tools setting.
     *
     * For a finding built before either was known. The security suite's "this half examined
     * nothing" notices are the case: they are produced INSIDE the audit or lint half, at a moment
     * when that half has just failed and the other has not run yet — so the only profile available
     * to them is a placeholder, and a placeholder in a notice whose whole purpose is to speak
     * honestly about the run is a contradiction a consumer reads in the JSON.
     *
     * The driver is deliberately NOT taken along. A notice saying "this half examined nothing"
     * names no engine, and borrowing `pgsql` from the half that did run would attach it to a
     * sentence that would read identically on MySQL — the same argument the analyse half already
     * makes for its own `unknown`.
     */
    public function withRunFlags(string $profile, bool $strictTools): self
    {
        return new self($this->driver, $profile, $strictTools, $this->resolvedServerVersion, $this->connection, $this->instanceRole, $this->pathBinding, $this->serverLifetime);
    }

    /**
     * A deterministic array projection with a fixed key order. An unknown server
     * version is omitted rather than serialized as null, so a reader can tell
     * "no version detected" from a real one. Carries the connection-level context
     * only — never a DSN or password.
     *
     * @return array<string, string|bool>
     */
    public function toArray(): array
    {
        $projection = [
            'driver' => $this->driver,
            'profile' => $this->profile,
            'strict_tools' => $this->strictTools,
            'server_version' => match ($this->serverVersion instanceof ServerVersion) {
                true => sprintf('%d.%d.%d', $this->serverVersion->major, $this->serverVersion->minor, $this->serverVersion->patch),
                false => null,
            },
            // Omitted, like the version, when there is none — a lint run over files has no
            // instance, and an `instance_role: null` on every migration finding would be noise
            // that also made the audit's real value harder to spot.
            'instance_role' => $this->instanceRole,
        ];

        return array_filter($projection, static fn (string|bool|null $value): bool => $value !== null);
    }
}
