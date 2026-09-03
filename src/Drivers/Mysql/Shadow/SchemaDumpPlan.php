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
 * are kept so a run can show what it did not replay and why, rather than leaving a
 * silent gap between the dump and the rebuilt database.
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
