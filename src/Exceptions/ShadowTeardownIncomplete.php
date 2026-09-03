<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;
use Throwable;

/**
 * A shadow teardown finished with databases still on the server, and it names WHICH.
 *
 * A PostgreSQL shadow run creates two databases — a template carrying the project's whole schema,
 * and a clone made from it — so "the teardown failed" is not one fact. It used to be reported as
 * one: teardown dropped the clone and then the template, in that order and in one statement each,
 * so a clone whose drop threw took the template's drop with it. The template is the worse of the
 * two leaks by a distance, since it holds the schema, and it was the one that could not be reached.
 *
 * Worse, the report that reached the user named the CLONE, always — because that is the field the
 * result was built from. A reader following it went looking for a database that was already gone
 * while the one still sitting there went unnamed. That is a silent green with an alibi.
 *
 * So teardown now attempts every database it created, whatever happened to the one before, and
 * carries the ones that survived in here. The message names them, because a leak the user cannot
 * find is a leak they cannot remove.
 */
final class ShadowTeardownIncomplete extends RuntimeException
{
    /**
     * @param  array<string, Throwable>  $failures  database name => why its removal failed
     */
    private function __construct(public readonly array $failures)
    {
        $names = array_keys($failures);

        parent::__construct(sprintf(
            'the shadow teardown left %d database(s) on the server: %s',
            count($names),
            implode(', ', $names),
        ));
    }

    /**
     * @param  array<string, Throwable>  $failures  database name => why its removal failed
     */
    public static function for(array $failures): self
    {
        return new self($failures);
    }

    /**
     * The databases still on the server, in the order they were attempted.
     *
     * @return list<string>
     */
    public function leaked(): array
    {
        return array_keys($this->failures);
    }
}
