<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Subjects\MigrationDirection;

/**
 * Where a tool's finding actually is: the migration, the statement inside it, and the objects
 * that statement acts on.
 *
 * The triple every downstream step reads. A finding mapper needs the statement to decide which
 * SQLens rule the tool's rule corresponds to; de-duplication needs it to tell "the same problem,
 * reported twice" from "two problems"; and a report needs the file to point a reader at
 * something they can open.
 */
final readonly class ToolPosition
{
    /**
     * @param  list<StatementTarget>|null  $targets  the objects this statement acts on, or null
     *                                               when the statement is not classified. Null
     *                                               rather than an empty list, which would read
     *                                               as "acts on nothing" — a claim, where null is
     *                                               the absence of one.
     */
    public function __construct(
        public string $file,
        public string $migrationClass,
        public int $statementIndex,
        /**
         * Up or down. It travels because a finding has to say which direction it is about — the
         * same statement index means a different statement in a rollback, and a report that left
         * it out would point a reader at the wrong half of the migration.
         */
        public MigrationDirection $direction,
        public ?array $targets,
    ) {}
}
