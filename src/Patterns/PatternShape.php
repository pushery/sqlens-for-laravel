<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

/**
 * What an index could serve in the pattern of a statement on one table: the columns it compares with a
 * value, the columns it bounds, the columns it sorts by, and the columns it asks to be null or not.
 *
 * Read by {@see PatternShapes} from the masked text of a {@see QueryPattern}, so it holds column names
 * and never a value.
 */
final readonly class PatternShape
{
    /**
     * @param  list<string>  $equality  compared with a value, `=` or `IN`, in the order they appear
     * @param  list<string>  $range  bounded, `<`, `<=`, `>`, `>=` or `BETWEEN`, in the order they appear
     * @param  list<string>  $sort  the leading columns of `ORDER BY`, all in one direction
     * @param  array<string, bool>  $nulls  column => true for `IS NULL`, false for `IS NOT NULL`
     */
    public function __construct(
        public string $table,
        public ?string $schema,
        public array $equality,
        public array $range,
        public array $sort,
        public array $nulls,
    ) {}

    /** @return list<string> every column the shape names */
    public function columns(): array
    {
        return array_values(array_unique([...$this->equality, ...$this->range, ...$this->sort, ...array_keys($this->nulls)]));
    }
}
