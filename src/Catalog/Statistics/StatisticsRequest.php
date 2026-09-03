<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Exceptions\InvalidStatisticsRequest;

/**
 * What a statistics reading was ASKED for — a named list of objects, never an instance-wide sweep.
 *
 * The narrowness is the design rather than a limitation of it. Statistics do not produce findings;
 * they weight findings that already exist, so the objects worth reading about are exactly the ones
 * some finding already references. Everything else is load on a production database at the one
 * moment — immediately before a deploy — when nobody wants any.
 *
 * That is why an empty object list is REFUSED instead of meaning "everything". The full-sweep
 * reading is the one somebody gets by forgetting to pass their list, and it arrives silently: a
 * bigger answer than was asked for, with the cost landing somewhere nobody is watching. A caller
 * with nothing to look up builds no request.
 *
 * The scope fields mirror {@see CatalogRequest} on purpose. Two readings of
 * the same database under different prefixes are readings of different questions, and a comparison
 * across them would report the question's shape as a change in the data — so the scope travels with
 * the request, and the request travels on the snapshot.
 */
final readonly class StatisticsRequest
{
    /** @var list<string> */
    public array $objects;

    /** @var list<string> */
    public array $schemas;

    /**
     * @param  list<string>  $objects  the qualified names some finding references. Required and
     *                                 non-empty; deduplicated and sorted here so two callers that
     *                                 assembled the same set in different orders produce the same
     *                                 request, and therefore the same snapshot hash.
     * @param  list<string>  $schemas  the schemas those objects live in; empty defers to whatever
     *                                 the reader resolves as the default scope, exactly as a catalog
     *                                 request does. A deliberate deferral, not a wildcard.
     */
    public function __construct(
        array $objects,
        array $schemas = [],
        /**
         * The table prefix to strip when naming objects, `''` for none.
         *
         * Stripped rather than ignored, for the reason a catalog reading strips it: a project that
         * set `prefix => 'acme_'` thinks in terms of `orders`, and statistics attached to
         * `acme_orders` are statistics about a table they do not believe they have.
         */
        public string $tablePrefix = '',
        /**
         * This reading's share of the run's time budget, in milliseconds.
         *
         * A share rather than a limit of its own: the deploy gate promises a bounded turnaround, and
         * a statistics reading is one part of it. Zero is refused — it does not express restraint,
         * it expresses a reading that cannot happen while reporting every object as skipped.
         */
        public int $budgetMilliseconds = 2_000,
    ) {
        if ($objects === []) {
            throw InvalidStatisticsRequest::namesNoObjects();
        }

        foreach ($objects as $object) {
            if (trim($object) === '') {
                throw InvalidStatisticsRequest::namesAnEmptyObject();
            }
        }

        if ($budgetMilliseconds <= 0) {
            throw InvalidStatisticsRequest::hasNoTimeBudget($budgetMilliseconds);
        }

        $objects = array_values(array_unique($objects));
        sort($objects);
        $schemas = array_values(array_unique($schemas));
        sort($schemas);

        $this->objects = $objects;
        $this->schemas = $schemas;
    }

    /** Whether this request asks about a given object, by its qualified name. */
    public function wants(string $object): bool
    {
        return in_array($object, $this->objects, true);
    }

    /**
     * @return array{objects: list<string>, schemas: list<string>, table_prefix: string, budget_ms: int}
     */
    public function toArray(): array
    {
        return [
            'objects' => $this->objects,
            'schemas' => $this->schemas,
            'table_prefix' => $this->tablePrefix,
            'budget_ms' => $this->budgetMilliseconds,
        ];
    }
}
