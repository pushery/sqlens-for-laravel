<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Connection;
use Illuminate\Database\DatabaseManager;
use Pushery\SQLens\Contracts\SessionDefenses;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Builds the reader its OWN named connection, from a copy of the application's config.
 *
 * The copy is the whole idea. Bounding the application's connection would work — and would leave
 * the host application running under SQLens's timeouts and read-only seal long after the audit
 * finished. A tool that changes the behavior of the code it was pointed at has done something worse
 * than the problem it was looking for.
 *
 * A separate name gives a separate PDO handle (verified against the installed framework), so the
 * two sessions cannot reach into each other: the reader's `SET`s are its own, and the application's
 * connection is byte-for-byte what it was before.
 */
final readonly class ReaderConnectionFactory
{
    /** The suffix that makes the reader's connection name recognizable in a stack trace. */
    public const string NAME_SUFFIX = '::sqlens_reader';

    /**
     * The suffix for a reader pointed at a THROWAWAY database rather than the project's.
     *
     * Its own suffix, and that is the load-bearing part. The database manager caches by name, so
     * reusing {@see NAME_SUFFIX} would overwrite the connection the running audit is reading
     * through — silently, because the name would be identical, and the audit would then report on
     * a disposable copy as though it were the project. The same class of mistake the pinned-host
     * purge below already had to be built for.
     */
    public const string SHADOW_NAME_SUFFIX = '::sqlens_shadow_reader';

    public function __construct(
        private DatabaseManager $database,
        private Repository $config,
    ) {}

    /**
     * The SOURCE connection a reader connection was derived from — the name a user configured, and
     * the one a finding has to quote.
     *
     * A catalog finding is about one instance, and "a foreign key is unindexed" is unactionable on
     * a project with more than one database without saying which. The reader connection carries a
     * suffixed name of this factory's own making, so recovering the source belongs HERE, where both
     * halves of that name are defined, rather than in each caller that would have to know the
     * suffix. A connection this factory never made is returned unchanged, which is also correct:
     * that IS its name.
     */
    public static function sourceOf(Connection $connection): string
    {
        $name = (string) $connection->getName();

        return str_ends_with($name, self::NAME_SUFFIX)
            ? substr($name, 0, -strlen(self::NAME_SUFFIX))
            : $name;
    }

    /**
     * A sealed reader connection pointed at a shadow database on the source's server.
     *
     * The shadow carries a GENERATED name on the same instance, so only `database` moves — the host,
     * port and credentials are the source's, because the shadow was created there. That is the whole
     * difference from {@see forConnection()}, and it is why this cannot be a flag on that one: the
     * two differ in what they may overwrite, not merely in what they set.
     *
     * `read`/`write` are dropped for the same reason as there, and it bites harder here: a reference
     * catalog read from a replica would be the expectation side of a comparison taken from a server
     * that never ran the migrations. A drift report built on that would be confidently wrong.
     *
     * The connection is rebuilt on every call rather than cached, because the shadow database name
     * is different every run — a cached entry under this name would point at a database that has
     * already been dropped, and the failure would arrive as a connection error naming a database
     * nobody recognizes.
     *
     * @throws UnknownReaderConnection when the source connection is not configured
     */
    public function forShadowDatabase(string $source, string $database): Connection
    {
        $name = $source.self::SHADOW_NAME_SUFFIX;
        $settings = $this->config->get('database.connections.'.$source);

        if (! is_array($settings)) {
            throw new UnknownReaderConnection($source);
        }

        unset($settings['read'], $settings['write']);
        $settings['database'] = $database;

        // Purged before it is set, not after: the manager holds a live handle under this name from
        // the previous run, and `config()->set()` alone does not reach an already-resolved
        // connection. Without the purge the second shadow read of a process silently answers from
        // the first shadow's database.
        $this->database->purge($name);
        $this->config->set('database.connections.'.$name, $settings);

        return $this->database->connection($name);
    }

    /**
     * The reader connection for an application connection name.
     *
     * Idempotent: asking twice for the same source returns the same connection, because the
     * database manager caches by name — so a run does not accumulate sessions on the server it is
     * trying not to burden.
     *
     * @param  string|null  $pinnedHost  the ONE host this run addresses, when the configuration
     *                                   offered a choice. Written onto the reader's own copy of the
     *                                   config, never onto the application's.
     */
    public function forConnection(string $source, ?string $pinnedHost = null): Connection
    {
        $name = $source.self::NAME_SUFFIX;
        $existing = $this->config->get('database.connections.'.$name);

        // A cached connection whose host is not the one this run pinned is the wrong server, and
        // reusing it would answer a question about a database nobody asked about — quietly, because
        // the name is identical. Rebuilt instead: the name is part of the contract
        // ({@see self::sourceOf()}) and so cannot carry the host, which leaves purging as the only
        // way for a second pin in one process to actually take effect.
        if (is_array($existing) && ($existing['host'] ?? null) !== $pinnedHost && $pinnedHost !== null) {
            $this->database->purge($name);
            $existing = null;
        }

        if ($existing === null) {
            $settings = $this->config->get('database.connections.'.$source);

            if (! is_array($settings)) {
                throw new UnknownReaderConnection($source);
            }

            // The read/write split is dropped on purpose. A catalog audit is a statement about ONE
            // instance, and a connection that silently sends reads to a replica would produce a
            // snapshot of a database nobody asked about — including one whose replication lag makes
            // it a different schema. Which instance is audited becomes an explicit choice.
            unset($settings['read'], $settings['write']);

            // The pinned host replaces whatever the base config named. Dropping the split above is
            // not enough on its own: a connection configured ONLY through read/write blocks has no
            // base host at all, and the reader would then connect to whatever the driver defaults
            // to — a server nobody named, reported as the project's.
            if ($pinnedHost !== null) {
                $settings['host'] = $pinnedHost;
            }

            $this->config->set('database.connections.'.$name, $settings);
        }

        return $this->database->connection($name);
    }

    /**
     * The SEALED session a preflight reads through, or the reason there is none.
     *
     * It hands back a session rather than a connection, and that is not convenience. The console
     * layer may not name a database class at all — the purity guard says so, and it is right: a
     * command that held a `Connection` is a command one line away from querying through it. Handing
     * it a sealed session gives it everything it needs and nothing it should not have.
     *
     * Answers with a session OR a named reason, never an exception: this runs inside a gate, and a
     * gate that dies on its own configuration has blocked a deploy without saying anything about the
     * database.
     *
     * The REAL server version comes back with it, read through the identity reader the rest of the
     * package already uses — never a second way to ask, because the whole point of the check that
     * consumes it is that one of two answers is wrong.
     *
     * It is resolved HERE rather than handed to the caller as a connection, and the reason is a
     * collision between two of this repo's own rules: the console may name no database class, and
     * Rector rewrites a null check on one into an `instanceof` that names it. Returning the parsed
     * version instead means the console never holds a connection at all, which satisfies both
     * without either being weakened.
     *
     * A version the server would not give comes back null rather than guessed. The check turns that
     * into a named `undetermined`; a plausible number here would make the comparison agree with
     * itself.
     *
     * The READERS come back with it for the same reason, and it is the one that made this a value
     * object rather than a longer list: a check needing statistics or live activity would otherwise
     * have to build its own, which needs the connection the console may not hold.
     */
    public function forPreflight(SessionDefenses $defenses, CatalogReaderFactory $readers, SubjectContext $context, ?string $pinnedHost = null): PreflightResolution
    {
        $resolution = PreflightConnection::resolve($this->config);

        if ($resolution->name === null) {
            return PreflightResolution::refused($resolution->skip ?? CatalogSkip::for(
                SchemaObjectType::Database,
                '(none)',
                SkipReason::NotReadable,
                'no preflight connection could be resolved, and this reading will not fall back to '
                .'the connection that runs your migrations.',
            ));
        }

        try {
            $connection = $this->forConnection($resolution->name, $pinnedHost);
        } catch (UnknownReaderConnection) {
            // Belt and braces with the resolution's own check, and not redundant: the resolution
            // reads the config, this reaches the manager, and a connection can be removed between
            // the two. Either way the answer is a reason rather than a throw.
            return PreflightResolution::refused(CatalogSkip::for(
                SchemaObjectType::Database,
                $resolution->name,
                SkipReason::NotReadable,
                'the preflight connection named in configuration could not be opened, and this '
                .'reading will not fall back to the connection that runs your migrations.',
            ));
        }

        $driver = (string) $connection->getDriverName();

        if (! $readers->supports($driver)) {
            // A driver this build has no readers for is a NAMED refusal, not an exception. The gate
            // runs inside a deploy script, and a throw there stops the deploy with a stack trace
            // instead of a sentence — about a scope decision this package made, not about anything
            // wrong with the database.
            return PreflightResolution::refused(CatalogSkip::for(
                SchemaObjectType::Database,
                $driver,
                SkipReason::UnsupportedDriver,
                sprintf(
                    'the "%s" driver has no catalog readers in this build, so a preflight against it '
                    .'could not read anything — including the server version every later check is '
                    .'measured against. This is a named absence rather than an empty run: a gate '
                    .'that answered clean here would have looked at nothing.',
                    $driver,
                ),
            ), $driver);
        }

        // Built ONCE and reused, deliberately. `CatalogReaderFactory::for()` constructs a fresh set
        // each call, so asking it three times would hand three checks three different reader objects
        // over the same connection — harmless today and exactly the kind of thing that stops being
        // harmless the first time a reader caches anything.
        $built = $readers->for($driver, $connection, $this->budget(), $context);

        $identity = $built->identity->read($resolution->name);

        // An `if` rather than a ternary, and the reason is the coverage report rather than taste:
        // a bare `: null` arm is EXECUTED and still counted uncovered by the driver, so the line
        // shows up as a gap nobody can close by writing a test. Spelling it out makes the
        // measurement match what actually runs.
        $parsed = null;

        if (is_string($identity->serverVersion)) {
            $parsed = ServerVersion::parse($identity->serverVersion, $driver);
        }

        return PreflightResolution::resolved(
            session: $this->sessionFor($connection, $defenses),
            driver: $driver,
            serverVersion: $parsed instanceof ServerVersion ? $parsed : null,
            advisory: $resolution->advisory(),
            // No `readerSkip` alongside them, and that is a MEASURED correction rather than an
            // omission. The first version carried one, on the assumption that a supported driver
            // could still implement only half the reader set. It cannot: `supports()` is asked above
            // and answers from the same builder map `for()` reads, so a driver that gets this far
            // has a builder, and every builder in this package returns a complete set. The coverage
            // gate found the else branch unreachable, which is what that guarantee looks like from
            // the outside.
            //
            // If a partial driver is ever wanted, the honest place to express it is `supports()` —
            // one question with one answer — not a second, quieter check here that would let a
            // half-supported driver through the first gate and stop it at the second.
            statistics: $built->statistics,
            activity: $built->activity,
            migrationRole: $resolution->migrationRole,
        );
    }

    /**
     * Seal a connection read-only, using a defense chosen by something that knows the engines.
     *
     * The construction lives here and the CHOICE arrives as an argument, and both halves matter.
     * This namespace may hold a database class; the console layer may not, so a command that built
     * the session itself would have to name one. And this namespace may not know an engine, so the
     * defense cannot be picked here either. Splitting it that way is what lets both rules hold.
     */
    public function sessionFor(Connection $connection, SessionDefenses $defenses): ReaderSession
    {
        return new ReaderSession($connection, $defenses->for((string) $connection->getDriverName()), $this->budget());
    }

    /** The configured budget, refusing the values that would remove the bound. */
    public function budget(): SessionBudget
    {
        return SessionBudget::of(
            $this->intSetting('statement_timeout', SessionBudget::DEFAULT_STATEMENT_TIMEOUT_MS),
            $this->intSetting('lock_timeout', SessionBudget::DEFAULT_LOCK_TIMEOUT_MS),
            $this->intSetting('idle_in_transaction_timeout', SessionBudget::DEFAULT_IDLE_IN_TRANSACTION_TIMEOUT_MS),
            $this->stringSetting('application_name', SessionBudget::DEFAULT_APPLICATION_NAME),
            $this->readBudgetMs(),
        );
    }

    /** The whole-reading budget, or the documented default when a project has not stated one. */
    private function readBudgetMs(): int
    {
        $value = $this->config->get('sqlens.catalog.budget_ms');

        return is_int($value) ? $value : SessionBudget::DEFAULT_READ_BUDGET_MS;
    }

    /**
     * ⚠️ ABSENT AND WRONG ARE DIFFERENT, AND TREATING THEM ALIKE CRASHED A RUN.
     *
     * This used to return 0 for anything that was not an integer, absence included, and the
     * budget refuses a 0 by name — so a config that simply did not mention `statement_timeout`
     * ended the run with an uncaught `InvalidSessionBudget`. Nothing catches that exception
     * anywhere in the package, so the user got a stack trace instead of the misconfiguration
     * exit code, and the message named a value they had never written: "0 would mean wait
     * forever".
     *
     * Two ordinary situations produce an absent key, and neither is a mistake:
     *
     *   * a config PUBLISHED by an earlier version, which froze before this key existed. Every
     *     consuming app that ran `vendor:publish` has one, and it never gains a key again.
     *   * a config written with only the keys the project cares about, which is what the
     *     documentation recommends over copying the whole file.
     *
     * So absence takes the shipped default — exactly the treatment `readBudgetMs()` below has
     * always given its own key, which is why that one never had this defect.
     *
     * A value that IS present and is not an integer keeps the old behavior: it reaches the
     * budget as a zero and the budget refuses it, naming the key. That is the case the original
     * reasoning was about, and reading a typo as "no limit" would silently unbound a reader
     * pointed at production.
     */
    private function intSetting(string $key, int $default): int
    {
        $value = $this->config->get('sqlens.catalog.session.'.$key);

        if ($value === null) {
            return $default;
        }

        return is_int($value) ? $value : 0;
    }

    /** Absent takes the shipped name; present-but-not-a-string stays a refusal. See intSetting(). */
    private function stringSetting(string $key, string $default): string
    {
        $value = $this->config->get('sqlens.catalog.session.'.$key);

        if ($value === null) {
            return $default;
        }

        return is_string($value) ? $value : '';
    }
}
