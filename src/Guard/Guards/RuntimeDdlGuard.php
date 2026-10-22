<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Guards;

use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Guard\Contracts\PausesDuringMigrations;
use Pushery\SQLens\Guard\Contracts\QueryInspector;
use Pushery\SQLens\Guard\GuardProfile;
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
 * the same job issues before it migrates is still DDL outside any migration. The migrator announces no
 * end when a migration fails, so the next request, job or command ends the pause as well
 * ({@see PausesDuringMigrations}).
 */
final class RuntimeDdlGuard implements PausesDuringMigrations, QueryInspector
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

    /** Whether the migrator is running in this process, between its start and its end. */
    private bool $migrating = false;

    /**
     * @param  bool  $exempt  true in a console process that runs any other Artisan command, which is where
     *                        migrations, seeders and maintenance commands run
     */
    public function __construct(private readonly ViolationLogger $logger, private readonly bool $exempt = false) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return $profile->runtimeDdl;
    }

    public function migrationsStarted(): void
    {
        $this->migrating = true;
    }

    public function migrationsEnded(): void
    {
        $this->migrating = false;
    }

    /** A new request, job or command: a run of the migrator that never announced its end is over. */
    public function startWindow(): void
    {
        $this->migrating = false;
    }

    public function inspect(QueryExecuted $query, GuardProfile $profile): void
    {
        // Migrations, seeders and maintenance commands legitimately issue DDL. Reporting them would
        // produce a violation on every deploy, which is how a guardrail gets switched off in its
        // first week. A queue worker and the scheduler are not exempt (see APPLICATION_COMMANDS),
        // but a run of the migrator inside one is a migration all the same.
        if ($this->exempt || $this->migrating) {
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
