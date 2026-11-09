<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * The tables and columns a migration's `up()` asks about before it decides what to build, and
 * whether its `down()` can refuse, read statically by the pre-scan.
 *
 * `if (! Schema::hasTable('ledger')) { Schema::create('ledger', ...); }` builds the table only where
 * it is missing. On a database where an earlier install already holds it, `up()` builds nothing, and
 * a `down()` that drops it deletes rows this migration never wrote. The captured statements cannot
 * show that: under pretend the question is answered with nothing, so the `CREATE` is captured as if
 * it always ran. The parse is the one place the question can be seen.
 */
final readonly class FoundSubjects
{
    /**
     * @param  list<string>  $asked  the tables `up()` asks about, and the columns as `table.column`,
     *                               lower-cased and sorted, each named by a literal in the call
     * @param  bool  $downCanRefuse  whether `down()`, or a method it runs, can throw: a rollback that
     *                               refuses while the data is there takes nothing with it
     */
    public function __construct(
        public array $asked,
        public bool $downCanRefuse,
    ) {}
}
