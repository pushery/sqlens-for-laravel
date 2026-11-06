<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

/**
 * The shape of a statement, with every value it carries taken out, and a stable fingerprint of it.
 *
 * Two statements that differ only in their values have the same pattern, so the queries a request
 * ran can be grouped by it: one pattern run forty times is the shape a suspected N+1 has.
 * {@see QueryPatterns::of()} makes one from a statement and its connection.
 *
 * The fingerprint is the same for the same pattern on the same engine, on every machine and in every
 * process. It changes when {@see self::VERSION} does, which a release says in its changelog.
 */
final readonly class QueryPattern
{
    /** The rules a pattern is made by. A fingerprint stored under one version is compared only to fingerprints of that version. */
    public const int VERSION = 1;

    /**
     * @param  string  $sql  the statement with every value replaced by `?`, comments removed, unquoted words in lower case and whitespace reduced to single spaces
     * @param  string  $fingerprint  64 hexadecimal characters, the same for the same pattern, version and engine
     * @param  bool  $coarse  true where the connection's grammar is not known, so everything from the first quote to the last is masked as one span
     */
    public function __construct(
        public string $sql,
        public string $fingerprint,
        public bool $coarse,
    ) {}

    /** Whether two patterns are the same, by their fingerprints. */
    public function equals(self $other): bool
    {
        return hash_equals($this->fingerprint, $other->fingerprint);
    }
}
