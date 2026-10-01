<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use InvalidArgumentException;

/**
 * A schema scope the reading cannot honor — named, never silently skipped.
 *
 * Every case below produces a run that reads LESS than the project asked for, and in each the
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

    /**
     * The session's default scope, with nothing configured, names no schema the server has.
     *
     * @param  list<string>  $resolvedDefault  what the session resolved as its scope
     * @param  list<string>  $existing  the schemas the server has, its own bookkeeping left out
     */
    public static function defaultResolvedToNothing(array $resolvedDefault, array $existing): self
    {
        $named = array_values(array_filter($resolvedDefault, static fn (string $schema): bool => $schema !== ''));
        sort($existing);

        return new self(sprintf(
            'No schema is configured, and the reading session\'s default scope %s, so auditing it would '
            .'have reported nothing while looking like a clean run. On PostgreSQL the default is the '
            .'search_path as the reading role resolves it, which leaves out every schema that role has no '
            .'USAGE on; on MySQL it is the connection\'s current database, which a connection configured '
            .'without one does not have. Name the schemas in sqlens.catalog.schemas, or give the reading '
            .'role USAGE on them. Available: %s.',
            $named === [] ? 'resolved to no schema at all' : 'names only schemas the server does not have or keeps for itself ('.implode(', ', $named).')',
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
