<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Usage;

/**
 * The counter behind one primary key, as far as a reading could see it.
 */
final readonly class KeyCounter
{
    /**
     * @param  string  $source  what feeds the key, in the words a finding uses for it: the sequence's
     *                          qualified name on PostgreSQL, `AUTO_INCREMENT` on MySQL
     * @param  int|null  $lastValue  the last value the counter handed out. Set when the state is
     *                               {@see KeyCounterState::Read} and only then.
     * @param  int|null  $ceiling  the counter's own maximum, where it has one apart from the column's
     *                             type: a PostgreSQL sequence's MAXVALUE. It can be lower than the
     *                             column allows, which is what a `serial` column keeps after it was
     *                             widened to `bigint`. Null on MySQL, where the column's type is the
     *                             counter's limit.
     * @param  string|null  $failure  why the position could not be read, with credentials removed. Set
     *                                when the state is {@see KeyCounterState::Unread}.
     */
    public function __construct(
        public string $source,
        public KeyCounterState $state,
        public ?int $lastValue = null,
        public ?int $ceiling = null,
        public ?string $failure = null,
    ) {}
}
