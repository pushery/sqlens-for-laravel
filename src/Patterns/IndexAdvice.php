<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

/**
 * The index advice for one query pattern: a suggested index with its DDL, the index that already
 * serves the pattern, or the reason the answer would be a guess.
 */
final readonly class IndexAdvice
{
    /**
     * @param  list<string>  $columns  the index columns, in their order
     * @param  list<string>  $supersedes  the indexes the suggested one leads with, which it makes redundant
     */
    private function __construct(
        public IndexAdviceStatus $status,
        public string $reason,
        public ?string $ddl = null,
        public array $columns = [],
        public ?string $coveredBy = null,
        public array $supersedes = [],
    ) {}

    /**
     * @param  list<string>  $columns
     * @param  list<string>  $supersedes
     */
    public static function suggested(string $ddl, array $columns, array $supersedes, string $reason): self
    {
        return new self(IndexAdviceStatus::Suggested, $reason, ddl: $ddl, columns: $columns, supersedes: $supersedes);
    }

    /** @param  list<string>  $columns */
    public static function covered(string $index, array $columns, string $reason): self
    {
        return new self(IndexAdviceStatus::Covered, $reason, columns: $columns, coveredBy: $index);
    }

    public static function undetermined(string $reason): self
    {
        return new self(IndexAdviceStatus::Undetermined, $reason);
    }
}
