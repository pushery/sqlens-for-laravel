<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use InvalidArgumentException;

/**
 * The write side of a connection leaves more than one server open, and nothing said which one the
 * deploy commands should read.
 *
 * Laravel shuffles a `host` list and picks one entry of a `write` list at random, so two runs can
 * reach two servers. Refused rather than left to the framework: a preflight, a drift comparison or a
 * verification about a server nobody chose reads exactly like one about the right server.
 */
final class AmbiguousPrimaryHost extends InvalidArgumentException
{
    /** @param  list<string>  $hosts */
    public function __construct(string $source, array $hosts, ?string $pinnedHost)
    {
        parent::__construct(sprintf(
            'The connection "%s" writes to more than one server (%s), and Laravel picks one of them at '
            .'random. The deploy commands read the server the migrations run on, so they need to know '
            .'which one: set sqlens.host to one of these hosts.%s',
            $source,
            implode(', ', $hosts),
            $pinnedHost === null ? '' : sprintf(' It is set to "%s", which the write side does not offer.', $pinnedHost),
        ));
    }
}
