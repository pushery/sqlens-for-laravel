<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Guards;

use Illuminate\Database\Events\QueryExecuted;
use Pushery\SQLens\Categories\Category;
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
 * ## Migrations are excluded by the ARTISAN CONTEXT, not by the statement
 *
 * A `CREATE TABLE` from `php artisan migrate` and one from a controller are the same statement, so
 * no amount of SQL reading separates them. What separates them is that one runs in a console
 * process and the other does not — and this guard is a runtime guard: an application serving a
 * request has no business issuing DDL, whatever the statement says.
 */
final readonly class RuntimeDdlGuard implements QueryInspector
{
    /**
     * The leading keywords that make a statement DDL.
     *
     * Matched on the FIRST word rather than searched for anywhere in the statement. `select * from
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
     * What it CANNOT read is a statement that opens with a comment, and that case is reported as
     * `undetermined` rather than waved through.
     *
     * @var list<string>
     */
    private const array DDL_KEYWORDS = ['create', 'alter', 'drop', 'truncate', 'rename', 'comment'];

    public function __construct(private ViolationLogger $logger, private bool $inConsole = false) {}

    public function appliesTo(GuardProfile $profile): bool
    {
        return $profile->runtimeDdl;
    }

    public function inspect(QueryExecuted $query, GuardProfile $profile): void
    {
        // A console process is where migrations, seeders and maintenance commands live, and all
        // three legitimately issue DDL. Reporting them would produce a violation on every deploy,
        // which is how a guardrail gets switched off in its first week.
        if ($this->inConsole) {
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
            message: 'a running request changed the schema, outside any migration',
            connection: $query->connectionName,
            sql: $query->sql,
            bindings: $query->bindings,
        ));
    }

    /**
     * Whether the statement begins with a comment, hiding its keyword from a first-word reading.
     *
     * Both SQL comment forms, because both are produced by real tooling: the double-dash form by
     * hand-written migrations, and the block form by query-tagging middleware, which prepends a
     * comment to every statement an application runs.
     */
    private function opensWithComment(string $sql): bool
    {
        $sql = ltrim($sql);

        return str_starts_with($sql, '--') || str_starts_with($sql, '/*');
    }

    private function isDdl(string $sql): bool
    {
        $first = strtolower(strtok(ltrim($sql), " \t\n\r") ?: '');

        return in_array($first, self::DDL_KEYWORDS, true);
    }
}
