<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Usage;

use Pushery\SQLens\Catalog\CatalogSnapshot;

/**
 * How far the counter behind each primary key has got.
 *
 * ## Why this is its own reading and not part of the snapshot
 *
 * Three reasons, and each alone would be enough.
 *
 * - **The value moves.** A sequence advances with every insert while the schema stands still, so a
 *   {@see CatalogSnapshot} carrying it could no longer promise that two readings of an unchanged
 *   schema are identical, which is what the drift comparison relies on.
 * - **Reading it takes a lock.** On PostgreSQL the position of a sequence comes from
 *   `pg_sequence_last_value()`, which takes ROW EXCLUSIVE on the sequence until the transaction
 *   ends. That is the lock every `nextval()` takes, so it waits behind nothing an INSERT does not
 *   wait behind, but it can wait. MySQL reports a fresh AUTO_INCREMENT only through `SHOW CREATE
 *   TABLE`, which takes a metadata lock on the table. A reading that waits too long must cost the
 *   rules that needed it, never the catalog every other rule stands on.
 * - **It can be withheld.** The role the audit is recommended to run as may not see a sequence's
 *   position at all, and that answer belongs to the rules about the key rather than to the reading
 *   of the schema.
 *
 * ## What it covers
 *
 * The keys that can run out: a single-column primary key whose counter or column stops below the
 * widest integer. And a `bigint` key a narrower single-column foreign key references, because that
 * column runs out when the key's sequence passes the column's ceiling. Any other `bigint` key fed by
 * a `bigint` sequence is left out rather than read, because no table reaches that ceiling, and
 * reading it would take a lock for an answer nobody asks for. A table absent from the reading
 * therefore has no counter anybody needs, which a rule must keep apart from a reading that failed:
 * {@see self::$available} says which one it is.
 */
final readonly class KeyCounterReading
{
    /**
     * @param  array<string, KeyCounter>  $counters  table qualified name => the counter feeding its
     *                                               primary key
     * @param  bool  $available  whether the counters could be read at all
     * @param  string|null  $failure  why they could not, with credentials removed
     */
    public function __construct(
        public array $counters = [],
        public bool $available = true,
        public ?string $failure = null,
    ) {}

    /** The reading a driver returns when it could not read the counters at all. */
    public static function unavailable(string $failure): self
    {
        return new self([], false, $failure);
    }

    /** The counter feeding this table's primary key, or null when the reading has none for it. */
    public function counterOf(string $table): ?KeyCounter
    {
        return $this->counters[$table] ?? null;
    }
}
