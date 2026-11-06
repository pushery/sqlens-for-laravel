<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\MigrationsEnded;
use Illuminate\Database\Events\MigrationsStarted;
use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Guard\Contracts\AccumulatesPerWindow;
use Pushery\SQLens\Guard\Contracts\PausesDuringMigrations;
use Pushery\SQLens\Guard\Contracts\QueryInspector;
use Pushery\SQLens\Guard\Contracts\RuntimeGuard;
use Pushery\SQLens\Guard\Contracts\TracksUnitsOfWork;

/**
 * The one query listener the guard suite registers, however many query-based guardrails are on.
 *
 * ## Why one and not N
 *
 * Every listener on `QueryExecuted` runs for every query an application executes. Three guardrails
 * with a listener each is three closures on the hot path of a request that might run four hundred
 * queries — a cost that grows with the feature list, in a package whose whole promise is that it
 * only reads. One listener that fans out costs one closure, whatever gets added later.
 *
 * ## It applies to nothing when nothing asks for it
 *
 * `appliesTo()` answers false when no inspector wants this profile, so a profile that only sets
 * Eloquent strictness registers no query listener at all. "Off" has to mean absent rather than
 * cheap, and this is where that promise is actually kept for the expensive half of the suite.
 *
 * ## The connection filter lives here
 *
 * A profile may name the connections it watches. Applying that once, before the fan-out, is what
 * keeps every inspector free of the question — and what makes "this guardrail is off for that
 * connection" one line rather than a rule each inspector has to remember.
 */
final readonly class QueryWatcher implements RuntimeGuard
{
    /**
     * The framework's Artisan commands that run the migrator or prepare a database for it.
     *
     * For an inspector that follows units of work, a run of the migrator begins with the start of one of
     * these commands, before `MigrationsStarted`, and ends with the command. Two of them issue DDL
     * before the migrator starts: `migrate` creates the migrator's own table through `migrate:install` when
     * the database has none, and `migrate:fresh` empties the database through `db:wipe` before it calls
     * `migrate`. A command that another one calls with `$this->call()` announces no start of its own, so the
     * list names every command an application may start itself, not only the innermost one.
     *
     * `sqlens.guard.migration_commands` adds the commands that run the migrator that way, such as a tenancy
     * package's `tenants:migrate` or a command of the application's own that calls `migrate`.
     *
     * @var list<string>
     */
    public const array MIGRATION_COMMANDS = [
        'migrate',
        'migrate:install',
        'migrate:fresh',
        'migrate:refresh',
        'migrate:reset',
        'migrate:rollback',
        'db:wipe',
    ];

    /**
     * @param  list<QueryInspector>  $inspectors  in the order they will judge a query
     * @param  list<string>  $migrationCommands  the Artisan commands whose start begins a run of the migrator
     */
    public function __construct(
        private Dispatcher $events,
        private array $inspectors = [],
        private array $migrationCommands = self::MIGRATION_COMMANDS,
    ) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return array_any($this->inspectors, fn (QueryInspector $inspector): bool => $inspector->appliesTo($profile));
    }

    /**
     * The lifecycle events that end one accounting window, listened for by name.
     *
     * String class-names rather than imports, and that is a dependency decision rather than a style
     * one: `RequestHandled` lives in `illuminate/foundation` and the job events in
     * `illuminate/queue`, neither of which this package requires. Listening by name costs nothing
     * when the event never fires, and works exactly as well when it does.
     *
     * Without these the cumulative budget is dead from the second job onward in any long-lived
     * process — and dead in the way that looks healthiest: the log reports once and then goes quiet
     * forever, which reads like an application that got faster. The same three events end a pause of
     * the migrator that never ended ({@see PausesDuringMigrations}), for an inspector that does not follow
     * the units of work.
     *
     * @var list<string>
     */
    private const array WINDOW_ENDS = [
        'Illuminate\Foundation\Http\Events\RequestHandled',
        'Illuminate\Queue\Events\JobProcessing',
        'Illuminate\Console\Events\CommandStarting',
    ];

    /**
     * The two of those that begin a unit of work, a job or an Artisan command.
     *
     * An inspector that follows units hears them as the start of a unit rather than of a window
     * ({@see TracksUnitsOfWork}): one that begins while the migrator runs is part of that run.
     *
     * @var list<string>
     */
    private const array UNIT_STARTS = [
        'Illuminate\Queue\Events\JobProcessing',
        'Illuminate\Console\Events\CommandStarting',
    ];

    /**
     * The events that end a unit of work, one for each start, listened for by name for the same reason.
     *
     * A job ends processed or with its exception. One that fails for good reports `JobFailed` after that
     * exception, so listening for it too would end the job twice. A command ends with its exit code, also
     * when it throws.
     *
     * @var list<string>
     */
    private const array UNIT_ENDS = [
        'Illuminate\Queue\Events\JobProcessed',
        'Illuminate\Queue\Events\JobExceptionOccurred',
        'Illuminate\Console\Events\CommandFinished',
    ];

    public function activate(GuardProfile $profile): void
    {
        // Resolved once, at activation, rather than per query. Which inspectors a profile wants
        // cannot change during a request — the profile is immutable — so asking every query would
        // be the same answer computed four hundred times.
        $active = array_values(array_filter(
            $this->inspectors,
            static fn (QueryInspector $inspector): bool => $inspector->appliesTo($profile),
        ));

        // A statement an inspection causes is not inspected itself. The one way an inspection reaches
        // the database is its report: a log channel that writes to a watched connection runs a
        // statement, and judged again, a slow write is reported and that report writes again, as deep
        // as the stack goes. A handler that writes its row as unbound SQL would not even need to be slow.
        /** @var bool $inspecting set while the listener below inspects, and read by the call that re-enters it */
        $inspecting = false;

        $this->events->listen(QueryExecuted::class, static function (QueryExecuted $query) use ($active, $profile, &$inspecting): void {
            if ($inspecting || ! $profile->watches($query->connectionName)) {
                return;
            }

            $inspecting = true;

            try {
                self::inspectWithEach($active, $query, $profile);
            } finally {
                $inspecting = false;
            }
        });

        $windowed = array_values(array_filter(
            $active,
            static fn (QueryInspector $inspector): bool => $inspector instanceof AccumulatesPerWindow,
        ));

        if ($windowed === []) {
            return;
        }

        $migrationCommands = $this->migrationCommands;

        foreach (self::WINDOW_ENDS as $event) {
            $begins = in_array($event, self::UNIT_STARTS, true);

            $this->events->listen($event, static function (?object $fired = null) use ($windowed, $begins, $migrationCommands): void {
                // A command that runs the migrator begins the run with its own start, after the unit it is, so
                // the end of that unit ends the run as well. Only an inspector that follows units hears it: one
                // that does not would never hear the command end, and would stay paused past it.
                $migrates = $begins && in_array(self::commandOf($fired), $migrationCommands, true);

                foreach ($windowed as $inspector) {
                    if ($begins && $inspector instanceof TracksUnitsOfWork) {
                        $inspector->unitStarted(self::unitOf($fired));

                        if ($migrates) {
                            $inspector->migrationsStarted();
                        }
                    } else {
                        $inspector->startWindow();
                    }
                }
            });
        }

        // The migrator's own two ends, for the inspectors that stand still while it runs. Its events live in
        // illuminate/database, which this package requires, so they are imported rather than named. For an
        // inspector that follows units, the start of a command that runs the migrator has begun the run already.
        $pausing = array_values(array_filter(
            $active,
            static fn (QueryInspector $inspector): bool => $inspector instanceof PausesDuringMigrations,
        ));

        if ($pausing === []) {
            return;
        }

        $this->events->listen(MigrationsStarted::class, static function () use ($pausing): void {
            foreach ($pausing as $inspector) {
                $inspector->migrationsStarted();
            }
        });

        $this->events->listen(MigrationsEnded::class, static function () use ($pausing): void {
            foreach ($pausing as $inspector) {
                $inspector->migrationsEnded();
            }
        });

        // The ends of the jobs and commands, for the inspectors that follow them. The end of the one that ran the
        // migrator also ends a run whose end the migrator never announced.
        $following = array_values(array_filter(
            $active,
            static fn (QueryInspector $inspector): bool => $inspector instanceof TracksUnitsOfWork,
        ));

        if ($following === []) {
            return;
        }

        foreach (self::UNIT_ENDS as $event) {
            $this->events->listen($event, static function (?object $fired = null) use ($following): void {
                foreach ($following as $inspector) {
                    $inspector->unitEnded(self::unitOf($fired));
                }
            });
        }
    }

    /**
     * What the start and the end of a job or a command share: the job, or the command's input.
     *
     * Read off the event's public properties, `job` on the queue's events and `input` on the console's,
     * because those classes are listened for by name. An event dispatched by its name alone carries
     * nothing, and its unit is then unnamed.
     */
    private static function unitOf(?object $event): ?object
    {
        if ($event === null) {
            return null;
        }

        $properties = get_object_vars($event);
        $unit = $properties['job'] ?? $properties['input'] ?? null;

        return is_object($unit) ? $unit : null;
    }

    /**
     * The name of the Artisan command whose start an event announces, or null for a job or an event without one.
     *
     * Read off the public `command` property of `CommandStarting` for the reason unitOf() reads `input`.
     */
    private static function commandOf(?object $event): ?string
    {
        $command = $event === null ? null : (get_object_vars($event)['command'] ?? null);

        return is_string($command) ? $command : null;
    }

    /**
     * Hands one statement to every inspector the profile wants, in their order.
     *
     * @param  list<QueryInspector>  $active
     */
    private static function inspectWithEach(array $active, QueryExecuted $query, GuardProfile $profile): void
    {
        foreach ($active as $inspector) {
            $inspector->inspect($query, $profile);
        }
    }
}
