<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Guards;

use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Guard\Contracts\QueryInspector;
use Pushery\SQLens\Guard\Contracts\TracksUnitsOfWork;
use Pushery\SQLens\Guard\ExpectedSchemaChanges;
use Pushery\SQLens\Guard\GuardProfile;
use Pushery\SQLens\Guard\QueryWatcher;
use Pushery\SQLens\Guard\ViolationLogger;
use Pushery\SQLens\Guard\Violations\Violation;

/**
 * DDL executed by a running application, outside any migration.
 *
 * ## Why this is worth a guardrail
 *
 * A schema change that never went through a migration is invisible to every other tool in this
 * package: `sqlens:lint` reads migrations, and `sqlens:drift` finds the RESULT months later without
 * being able to say who did it or when. This catches it at the moment it happens, in the request
 * that did it, with the statement attached.
 *
 * It is also how a schema stops being reproducible. The next `migrate:fresh` on a rebuilt
 * environment silently loses whatever the runtime created.
 *
 * ## Migrations are excluded by the artisan context, not by the statement
 *
 * A `CREATE TABLE` from `php artisan migrate` and one from a controller are the same statement, so
 * no amount of SQL reading separates them. What separates them is the command the process runs:
 * `migrate` is an Artisan command, and a controller runs in a request — and this guard is a runtime
 * guard: an application serving a request has no business issuing DDL, whatever the statement says.
 *
 * A queue worker and the scheduler are Artisan commands as well, but what they run is the
 * application's own code, a job or a scheduled closure, so they are watched like a request
 * ({@see self::APPLICATION_COMMANDS}). Under Octane a worker is no console process at all: Octane's
 * bootstrap sets `APP_RUNNING_IN_CONSOLE` to false, so every request there is watched too.
 *
 * ## A migration the application runs itself is a migration too
 *
 * A watched process can run the migrator: a job that rebuilds a database with `Artisan::call('migrate')`,
 * a screen that migrates a tenant. Its statements are migrations, and reported they would bury the one
 * finding that matters under thousands of them. So the guardrail pauses while the migrator runs, from
 * `MigrationsStarted` to `MigrationsEnded`, and stays watching outside that run: a `CREATE DATABASE`
 * the same job issues before it migrates is still DDL outside any migration.
 *
 * Started as a command, a run covers the whole command. `migrate` creates the migrator's own table through
 * `migrate:install` before `MigrationsStarted`, and `migrate:fresh` drops every table first, so the pause
 * begins with the start of a command that runs the migrator and ends with that command
 * ({@see QueryWatcher::MIGRATION_COMMANDS}, and the commands `sqlens.guard.migration_commands` adds).
 *
 * A job or a command that starts while the migrator runs belongs to that run: a migration that dispatches
 * a job onto a synchronous queue, or calls `Artisan::call()`, runs it inside itself, and the pause holds
 * through it. The migrator announces no end when a migration fails, so the end of the job or the command
 * that ran it ends the pause as well, and the end of a request ends every pause ({@see TracksUnitsOfWork}).
 *
 * ## A change the application declares is no finding
 *
 * Some code changes a schema on purpose outside a migration: a job that creates the partition of the month ahead. It
 * says so with {@see ExpectedSchemaChanges::during()} and a reason, and while that work runs the guardrail reports no
 * DDL. The declaration is a block of work, never a form of statement, so the same statement anywhere else is reported.
 */
final class RuntimeDdlGuard implements QueryInspector, TracksUnitsOfWork
{
    /**
     * The leading keywords that make a statement DDL.
     *
     * Matched on the first word rather than searched for anywhere in the statement. `select * from
     * audit where action = 'drop table'` contains the word and is not DDL, and a guard that reported
     * it would be teaching its reader to skim.
     *
     * ## Why the leading keyword and not the canonicalization layer
     *
     * The obvious answer is to canonicalize and read the statement kind, and this guardrail
     * deliberately does not — because canonicalizing means PARSING, and this runs on the query hot
     * path of every request an application serves. A parse per query is a cost every request pays
     * for a check that fires on almost none of them, and "no runtime-overhead feature through the
     * back door" is the promise this whole suite is measured against.
     *
     * The leading keyword survives the difference that would have justified a parser: identifier
     * quoting. A table name in double quotes, in backticks or bare all follow the same leading
     * word, so the drift a canonicalizer protects against is not drift this reading can suffer.
     *
     * What it cannot read is a statement that opens with a comment, and that case is reported as
     * `undetermined` rather than waved through. What it does not SEE is DDL behind a first word that
     * is not a keyword: a second statement after a semicolon in a call that sends several, such as
     * `DB::unprepared()`, and `SELECT … INTO`, which creates a table on PostgreSQL. Both pass in
     * silence, and that is the price of a reading that never parses.
     *
     * @var list<string>
     */
    private const array DDL_KEYWORDS = ['create', 'alter', 'drop', 'truncate', 'rename', 'comment'];

    /**
     * The Artisan commands that run the application's own code: the queue workers and the scheduler.
     *
     * A job and a scheduled closure are application code, where DDL is as out of place as in a request.
     * Every other command is exempt, because migrations, seeders and maintenance commands issue DDL
     * legitimately. A command the scheduler starts runs in a process of its own and is judged by its
     * own name.
     *
     * @var list<string>
     */
    public const array APPLICATION_COMMANDS = ['queue:work', 'queue:listen', 'horizon:work', 'schedule:run', 'schedule:work'];

    /** The id of a unit whose event carried no object. No object has the id 0. */
    private const int UNNAMED = 0;

    /**
     * The jobs and Artisan commands under way in this process, the outermost first, by object id.
     *
     * @var list<int>
     */
    private array $units = [];

    /**
     * For each run of the migrator under way, how many units were under way when it started.
     *
     * A run started among two units runs inside the second, and is over once fewer than two remain. A run
     * started among none runs in a request, and ends with the migrator or with the request.
     *
     * @var list<int>
     */
    private array $runs = [];

    /**
     * @param  bool  $exempt  true in a console process that runs any other Artisan command, which is where
     *                        migrations, seeders and maintenance commands run
     * @param  ExpectedSchemaChanges  $expected  the declarations of this process, the one the container holds
     */
    public function __construct(
        private readonly ViolationLogger $logger,
        private readonly bool $exempt = false,
        private readonly ExpectedSchemaChanges $expected = new ExpectedSchemaChanges,
    ) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return $profile->runtimeDdl;
    }

    public function migrationsStarted(): void
    {
        $this->runs[] = count($this->units);
    }

    /** The innermost run ended. A migration that calls the migrator itself runs one inside another. */
    public function migrationsEnded(): void
    {
        array_pop($this->runs);
    }

    public function unitStarted(?object $unit): void
    {
        $this->units[] = $unit === null ? self::UNNAMED : spl_object_id($unit);
    }

    public function unitEnded(?object $unit): void
    {
        $id = $unit === null ? self::UNNAMED : spl_object_id($unit);
        $positions = array_keys($this->units, $id, true);

        // An end whose start this guardrail never saw, because it was armed while the unit ran, changes nothing.
        if ($positions === []) {
            return;
        }

        // The innermost unit of that id ends, and a unit inside it that announced no end of its own is over
        // with it.
        $this->units = array_slice($this->units, 0, max($positions));

        // So is every run of the migrator that started inside it, announced or not.
        $open = count($this->units);
        $this->runs = array_values(array_filter($this->runs, static fn (int $startedAmong): bool => $startedAmong <= $open));
    }

    /** The request is over, and with it every unit and every run of the migrator inside it. */
    public function startWindow(): void
    {
        $this->units = [];
        $this->runs = [];
    }

    public function inspect(QueryExecuted $query, GuardProfile $profile): void
    {
        // Migrations, seeders and maintenance commands legitimately issue DDL. Reporting them would
        // produce a violation on every deploy, which is how a guardrail gets switched off in its
        // first week. A queue worker and the scheduler are not exempt (see APPLICATION_COMMANDS),
        // but a run of the migrator inside one is a migration all the same, and work the application declared
        // as a schema change is what it says it is.
        if ($this->exempt || $this->runs !== [] || $this->expected->underWay()) {
            return;
        }

        // A statement whose leading keyword cannot be read at this layer is UNDETERMINED, never
        // silently fine. A leading comment is the case that produces it — `/* from cache */ create
        // table …` is DDL that a first-word reading cannot see — and answering "not DDL" there
        // would be a guardrail reporting a clean result about something it never looked at.
        if ($this->opensWithComment($query->sql)) {
            $this->logger->record($profile, Violation::undetermined(
                type: 'runtime_ddl',
                category: Category::Safety,
                message: 'a statement opens with a comment, so whether it is DDL could not be read '
                    .'from its leading keyword. This guardrail judges the first keyword and nothing '
                    .'else — deliberately, because a parse per query is a cost every request pays.',
                reason: 'leading_comment_hides_keyword',
                connection: $query->connectionName,
                sql: $query->sql,
            ));

            return;
        }

        if (! $this->isDdl($query->sql)) {
            return;
        }

        $this->logger->record($profile, Violation::found(
            type: 'runtime_ddl',
            category: Category::Safety,
            message: 'the running application changed the schema, outside any migration',
            connection: $query->connectionName,
            sql: $query->sql,
            bindings: $query->bindings,
        ));
    }

    /**
     * Whether the statement begins with a comment, hiding its keyword from a first-word reading.
     *
     * All three comment forms, because all three are produced by real tooling: the double-dash form
     * by hand-written migrations, the block form by query-tagging middleware, which prepends a
     * comment to every statement an application runs — and the hash form, which is MySQL's third.
     *
     * Leaving one out is dangerous, not untidy. A form this method does not know does not fall to
     * `undetermined`: it falls through to `isDdl()`, which reads `#` as the leading word, does not
     * find it among the keywords, and returns in silence. Measured against 8.4.10, `# app=web`
     * followed by a `CREATE TABLE` creates the table, so without the hash form an application whose
     * middleware tags in that style would have this guardrail switched off, with nothing on the
     * surface to say so.
     *
     * MySQL's double-dash needs a following space or control character — `--x` is minus-minus
     * there, and this method calls it a comment anyway. That is the cautious direction (an
     * `undetermined` where MySQL would compute), so it stays; it is written down because the
     * asymmetry otherwise looks like a bug worth "fixing" in the direction that loses findings.
     */
    private function opensWithComment(string $sql): bool
    {
        $sql = $this->trimmed($sql);

        return str_starts_with($sql, '--') || str_starts_with($sql, '/*') || str_starts_with($sql, '#');
    }

    /**
     * Whether the statement's first word is a DDL keyword.
     *
     * The word is the run of letters at the start, so it ends wherever the engines end it: at any
     * whitespace, form feed and vertical tab included, at a parenthesis, and at a block comment
     * written straight after it. A keyword followed directly by a block comment or by a form feed
     * is a statement both engines run, and a split at the four common whitespace characters alone
     * read it as one word that is no keyword and stayed silent.
     */
    private function isDdl(string $sql): bool
    {
        $first = preg_match('/^[a-z]+/i', $this->trimmed($sql), $word) === 1 ? strtolower($word[0]) : '';

        return in_array($first, self::DDL_KEYWORDS, true);
    }

    /** The statement without its leading whitespace, form feed included, which `ltrim()` keeps. */
    private function trimmed(string $sql): string
    {
        return ltrim($sql, " \t\n\r\0\x0B\f");
    }
}
