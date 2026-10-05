<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Canonical\QuotedIdentifier;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * The name of a catalog object, written the way PostgreSQL reads an identifier.
 *
 * The catalog hands an object over by its display name, `public.German Phonebook`, which is not
 * SQL: unquoted, the space ends the name and the capitals are folded away. Split into its schema
 * and its own name and quoted part by part, it can only name the object the finding is about.
 */
final readonly class QuotedObjectName
{
    public static function of(SchemaObject $object): string
    {
        $schema = (string) $object->parent;
        $name = $object->qualifiedName;

        // An if, not a three-line ternary: the coverage driver never marks the else line of one
        // as run, so the floor would fail over formatting rather than over a missing test.
        if ($schema !== '' && str_starts_with($name, $schema.'.')) {
            $name = substr($name, strlen($schema) + 1);
        }

        return QuotedIdentifier::of('"', $schema, $name);
    }
}
