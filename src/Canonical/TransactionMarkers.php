<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * The transaction-control vocabulary a driver declares: the keywords that OPEN a
 * transaction (BEGIN, START) and those that CLOSE one (COMMIT, ROLLBACK, END),
 * upper case. The resolver reads these instead of hard-coding a marker set, so a
 * driver that spells its transaction control differently is honored — and a
 * driver that declares NO markers (both lists empty) is a named missing artifact,
 * not a silent "no transaction here".
 */
final readonly class TransactionMarkers
{
    /**
     * @param  list<string>  $openers
     * @param  list<string>  $closers
     */
    public function __construct(
        public array $openers,
        public array $closers,
    ) {}
}
