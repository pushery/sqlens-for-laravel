<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L2;

/**
 * What a foreign key points AT: the target table and the columns it references, read off the
 * canonical statement.
 *
 * A value object rather than a two-element array, because the rule branches on "is this a foreign
 * key at all" and then carries both parts through three messages. An array would have made "null
 * means not a foreign key" indistinguishable from "null means no columns", and the second is a
 * malformed statement rather than an ordinary one.
 */
final readonly class ForeignKeyReference
{
    /** @param  list<string>  $columns  the referenced columns, in the order the statement names them */
    public function __construct(
        public string $table,
        public array $columns,
    ) {}
}
