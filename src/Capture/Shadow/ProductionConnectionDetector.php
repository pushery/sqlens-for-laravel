<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use Illuminate\Contracts\Config\Repository;

/**
 * Decides whether a connection looks like it addresses a production instance —
 * the input the production guard uses to refuse a database-creating mode outright.
 *
 * It is a HEURISTIC and says so. There is no field in a Laravel connection that
 * declares "this is production", so the answer is read off the names a project
 * actually uses: the connection name and the database name. That means it can be
 * wrong, and the direction it is allowed to be wrong in is fixed: a false POSITIVE
 * costs a developer a refused shadow run they can rename around, while a false
 * NEGATIVE would let a mode that creates and drops databases loose on production.
 * So the markers are matched generously, and anything ambiguous counts as
 * production.
 *
 * It never connects. Reading a connection's config is enough, and a detector that
 * had to open the very connection it is protecting would be a contradiction.
 *
 * This is the LAST line, not the only one: the guard also requires an allowed
 * environment and an explicit confirmation. A project whose production connection
 * is named something this cannot recognize is still protected by those.
 */
final readonly class ProductionConnectionDetector
{
    /**
     * The substrings that mark a name as production. Matched case-insensitively
     * against both the connection name and the database name, on word-ish
     * boundaries so `production_replica` and `acme-prod` match while `reproduce`
     * and `probe` do not — a marker has to be a segment of the name, not a
     * coincidence inside a longer word.
     *
     * @var list<string>
     */
    public const array MARKERS = ['production', 'prod', 'live'];

    public function __construct(private Repository $config) {}

    /** Whether $connection addresses what looks like a production instance. */
    public function isProduction(string $connection): bool
    {
        $database = $this->config->get('database.connections.'.$connection.'.database');
        if ($this->marked($connection)) {
            return true;
        }

        return is_string($database) && $this->marked($database);
    }

    /**
     * Whether a name carries a production marker as one of its segments.
     *
     * Segments are split on the separators names actually use — underscore, dash,
     * dot, whitespace — and a segment matches when it IS a marker or starts with
     * one (so `prod`, `production`, `prod2` and `live1` match). Substring matching
     * anywhere in the name was rejected: it flags `reproduce` and `improved`, and a
     * detector that cries wolf gets worked around, which is worse than one that is
     * merely strict.
     */
    private function marked(string $name): bool
    {
        foreach (preg_split('/[^a-z0-9]+/i', strtolower($name)) ?: [] as $segment) {
            foreach (self::MARKERS as $marker) {
                if (str_starts_with($segment, $marker)) {
                    return true;
                }
            }
        }

        return false;
    }
}
