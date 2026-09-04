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
 * costs a developer a refused shadow run, while a false NEGATIVE would let a mode
 * that creates and drops databases loose on production. So the markers are matched
 * generously, and anything ambiguous counts as production.
 *
 * That asymmetry decides how a false positive is FIXED, and it is worth being exact about,
 * because this docblock used to say "a refused shadow run they can rename around" and treat the
 * rename as the answer. It is not one. Renaming a database is not a step a developer can take
 * casually — every environment file, every teammate's machine and every seeded fixture points at
 * the old name — and the reason for taking it is invisible from the refusal, which says
 * "production connection" rather than which word made it say so. A false positive common enough
 * to meet ordinary projects is therefore fixed HERE, by naming the coincidence, and not by asking
 * the project to change around it. See {@see self::COINCIDENCES}.
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

    /**
     * Segments that BEGIN with a marker without meaning one — a coincidence inside a longer word,
     * where the longer word is a thing projects really name their databases after.
     *
     * `livewire` is the case that produced this list. Livewire is one of the most
     * widespread Laravel packages, naming the database after the application is what Herd, Valet and
     * `laravel new` all do, and `livewire` starts with `live` — so an ordinary local database called
     * `acme_livewire_db` was read as production and every database-creating mode refused to run
     * against it, in `local`, with `--force`, with no way to tell from the message that a UI package
     * in the name was the reason.
     *
     * ## Why a list here rather than a tighter rule on the markers
     *
     * The obvious tightening — "the rest of the segment must be empty or numeric" — was measured
     * against what it would cost. It keeps `live`, `live1`, `prod2` and rejects `livewire`, and it
     * also rejects `livedb`, `proddb`, `liveserver` and `prodserver`: ordinary names for the exact
     * thing this detector exists to catch. That trades a false positive for a false NEGATIVE, and
     * the direction of this heuristic's error is not a preference — a false positive costs a
     * developer a refused run, a false negative costs a production database.
     *
     * ## Why a hand-typed list is acceptable HERE, when it usually is not
     *
     * A missing entry can only produce a false POSITIVE: a name that is refused when it need not
     * have been, loudly, with a message. It can never let a production database through. That
     * asymmetry is what makes the list safe to be incomplete — the failure mode of forgetting an
     * entry is the harmless one, and it announces itself. A list whose gaps went the other way would
     * have no business being typed by hand.
     *
     * @var list<string>
     */
    public const array COINCIDENCES = ['livewire'];

    public function __construct(private Repository $config) {}

    /** Whether $connection addresses what looks like a production instance. */
    public function isProduction(string $connection): bool
    {
        return $this->explain($connection) !== null;
    }

    /**
     * WHY the connection was read as production — the segment that matched and the marker it
     * matched — or null when nothing did.
     *
     * The verdict alone is not actionable. A refused run says "production connection", and somebody
     * looking at a database called `acme_livewire_db` has no way to get from that sentence to the
     * word that caused it; the person who reported this needed a second measurement, removing one
     * segment at a time, to find it. Naming the match turns a heuristic into something a reader can
     * argue with, which is the least a heuristic owes them.
     *
     * @return array{name: string, segment: string, marker: string}|null
     */
    public function explain(string $connection): ?array
    {
        $match = $this->markerIn($connection);

        if ($match !== null) {
            return ['name' => $connection, ...$match];
        }

        $database = $this->config->get('database.connections.'.$connection.'.database');

        if (! is_string($database)) {
            return null;
        }

        $match = $this->markerIn($database);

        return $match === null ? null : ['name' => $database, ...$match];
    }

    /**
     * The first segment of $name that carries a production marker, and the marker it carried.
     *
     * Segments are split on the separators names actually use — underscore, dash,
     * dot, whitespace — and a segment matches when it IS a marker or starts with
     * one (so `prod`, `production`, `prod2` and `live1` match). Substring matching
     * anywhere in the name was rejected: it flags `reproduce` and `improved`, and a
     * detector that cries wolf gets worked around, which is worse than one that is
     * merely strict.
     *
     * A segment on the coincidence list is skipped before any marker is tried, so a name can carry
     * `livewire` and still be caught by a `production` elsewhere in it — the exemption is for the
     * one segment, never for the whole name.
     *
     * @return array{segment: string, marker: string}|null
     */
    private function markerIn(string $name): ?array
    {
        foreach (preg_split('/[^a-z0-9]+/i', strtolower($name)) ?: [] as $segment) {
            if (in_array($segment, self::COINCIDENCES, true)) {
                continue;
            }

            foreach (self::MARKERS as $marker) {
                if (str_starts_with($segment, $marker)) {
                    return ['segment' => $segment, 'marker' => $marker];
                }
            }
        }

        return null;
    }
}
