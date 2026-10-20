<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

/**
 * A `schema:dump` split into what the shadow replay actually runs: an ordered list
 * of executable statements, and — separately, never discarded — the client
 * directives that were skipped.
 *
 * Order is the whole point on the executable side: a dump's statements have
 * dependencies (a table before its foreign key, a routine before a trigger that
 * calls it), so the plan preserves the dump's order exactly. The skipped directives
 * are kept beside them, each with the reason it was skipped, so the splitter's
 * decisions can be read and held one by one.
 *
 * A directive whose omission changes how the dump's statements ran, one that sets
 * `SQL_MODE` or `TIME_ZONE` to a value, becomes a note on the shadow session
 * ({@see SkippedDumpDirective::note()}), and the command that ran the capture writes
 * it on STDERR. No report carries it, because a report holds one result per migration.
 */
final readonly class SchemaDumpPlan
{
    /**
     * @param  list<string>  $statements  the executable statements, in dump order
     * @param  list<SkippedDumpDirective>  $skipped  the client directives not replayed
     */
    public function __construct(
        public array $statements,
        public array $skipped,
    ) {}
}
