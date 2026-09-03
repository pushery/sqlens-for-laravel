<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use InvalidArgumentException;

/**
 * A configured schema the reading cannot honor — named, never silently skipped.
 *
 * Both cases below produce a run that reads LESS than the project asked for, and in both the
 * tempting behavior is to quietly narrow the scope and finish green. That is the failure this
 * package refuses everywhere: an audit that examined nothing looks exactly like an audit that
 * examined everything and found nothing wrong.
 */
final class UnknownCatalogSchema extends InvalidArgumentException
{
    /** @param list<string> $existing */
    public static function doesNotExist(string $schema, array $existing): self
    {
        sort($existing);

        return new self(sprintf(
            'The configured schema "%s" does not exist on this server, so auditing it would have '
            .'reported nothing while looking like a clean run. Available: %s.',
            $schema,
            $existing === [] ? '(none)' : implode(', ', $existing),
        ));
    }

    public static function isTheServersOwn(string $schema): self
    {
        return new self(sprintf(
            'The schema "%s" is the server\'s own catalog and is never audited — every finding in it '
            .'would be about a table nobody in this project wrote. Remove it from sqlens.catalog.schemas '
            .'rather than expecting it to be read.',
            $schema,
        ));
    }
}
