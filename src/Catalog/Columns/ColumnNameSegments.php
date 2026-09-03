<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Columns;

/**
 * A column name broken into the pieces a name heuristic is allowed to match against.
 *
 * ## Why this is a class and not two private methods
 *
 * Two dictionaries in this package read column NAMES and guess what lives in them — the money one
 * and the privacy one. Written twice, the halves that must agree would be free to drift, and the
 * drift would be invisible: both would keep passing their own tests while disagreeing about whether
 * `birthDate` and `birth_date` are the same name.
 *
 * What they must agree on is the SEGMENTATION. What they may differ on is the predicate, and they
 * genuinely do — see the two `matches…` methods. So the segmentation lives here once and the
 * predicates are named rather than assumed.
 *
 * ## Two modes, because one of them would change a shipped rule
 *
 * {@see plain()} is exactly what the money dictionary has always done: lowercase, split on
 * underscores. {@see folded()} adds diacritic folding and camel-case splitting, which the privacy
 * dictionary needs because a German schema spells a name with an umlaut and a Laravel project
 * writes `birthDate`.
 *
 * Applying the folded mode to money would be a silent behavior change to a rule that already ships —
 * `creditCardAmount` would start reporting where it used to be quiet. That may well be an
 * improvement, and it is not this class's decision to make, so the old behavior keeps its own
 * entry point rather than being upgraded in passing.
 */
final readonly class ColumnNameSegments
{
    /**
     * @param  string  $whole  the normalized name, as one string
     * @param  list<string>  $segments  the normalized name, split
     */
    private function __construct(
        public string $whole,
        public array $segments,
    ) {}

    /** Lowercased and split on underscores. The money dictionary's long-standing behavior. */
    public static function plain(string $columnName): self
    {
        $name = mb_strtolower(trim($columnName));

        return new self($name, explode('_', $name));
    }

    /**
     * Additionally folds diacritics and splits camel case.
     *
     * The folding is a fixed map rather than a locale-aware transliteration, deliberately: an
     * `iconv` transliteration answers differently depending on the locale the process happens to be
     * running under, and this package's determinism rule forbids a reading that depends on the
     * machine. The map covers what the shipped dictionary needs and can grow with it.
     */
    public static function folded(string $columnName): self
    {
        $name = mb_strtolower(trim($columnName));

        // Camel case before folding: the boundary is between a lower and an upper character, and
        // lowercasing first would destroy it. So the split runs on the ORIGINAL.
        $split = mb_strtolower((string) preg_replace('/(?<=[a-z0-9])(?=[A-Z])/u', '_', trim($columnName)));

        $folded = strtr($split, [
            'ä' => 'ae', 'ö' => 'oe', 'ü' => 'ue', 'ß' => 'ss',
            'á' => 'a', 'à' => 'a', 'â' => 'a', 'ã' => 'a', 'å' => 'a',
            'é' => 'e', 'è' => 'e', 'ê' => 'e', 'ë' => 'e',
            'í' => 'i', 'ì' => 'i', 'î' => 'i', 'ï' => 'i',
            'ó' => 'o', 'ò' => 'o', 'ô' => 'o', 'õ' => 'o',
            'ú' => 'u', 'ù' => 'u', 'û' => 'u',
            'ç' => 'c', 'ñ' => 'n',
        ]);

        // `$name` is unused beyond this guard, and the guard is the point: an empty name must not
        // produce a single empty segment that an empty term could match.
        if ($name === '') {
            return new self('', []);
        }

        return new self($folded, array_values(array_filter(explode('_', $folded), static fn (string $s): bool => $s !== '')));
    }

    /**
     * Whether a term matches the whole name, or — for a single-word term — one whole segment.
     *
     * The money dictionary's rule. A multi-word term matches the WHOLE NAME only, which is narrow
     * on purpose: `amount_due` firing on any column with an `amount` segment would be the substring
     * failure by another route.
     *
     * @param  list<string>  $terms
     */
    public function matchesWholeOrSegment(array $terms): bool
    {
        return array_any(
            $terms,
            fn (string $term): bool => $this->whole === $term
                || (! str_contains($term, '_') && in_array($term, $this->segments, true)),
        );
    }

    /**
     * Whether a term matches the whole name, one whole segment, or a RUN of adjacent segments.
     *
     * The privacy dictionary's rule, and the difference is prefixes. A column is `user_iban` or
     * `customer_tax_id` far more often than it is bare `iban` or bare `tax_id`, so a multi-word term
     * that only matched the whole name would miss the common case rather than the rare one.
     *
     * It stays a boundary match: the run must be adjacent segments in order, so `tax_id` is found in
     * `customer_tax_id` and not in `tax_bracket_id`.
     *
     * @param  list<string>  $terms
     */
    public function matchesWholeOrRun(array $terms): bool
    {
        return array_any($terms, function (string $term): bool {
            if ($this->whole === $term) {
                return true;
            }

            $wanted = explode('_', $term);
            $length = count($wanted);

            if ($length === 1) {
                return in_array($term, $this->segments, true);
            }

            $available = count($this->segments);

            for ($i = 0; $i + $length <= $available; $i++) {
                if (array_slice($this->segments, $i, $length) === $wanted) {
                    return true;
                }
            }

            return false;
        });
    }
}
