<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Money;

use JsonException;
use Pushery\SQLens\Catalog\Columns\ColumnNameSegments;

/**
 * The column-name terms that suggest a column holds money — read from data, never hard-coded.
 *
 * A rule about floating-point money needs a name heuristic, and a name heuristic written as a regex
 * inside the rule is a heuristic nobody can review: a diff shows a changed pattern, not a changed
 * term. As a sorted artifact it reviews like a list, merges like a list, and a project can extend it
 * without forking the package.
 *
 * ## Two confidence levels, and the split is the whole point
 *
 * `price` and `rechnungsbetrag` mean money on their own. `value`, `rate` and `wert` name a hundred
 * things that are not money, and a rule firing on them would be noise nobody reads — so a weak term
 * needs a second signal, which the RULE decides and this dictionary does not. Collapsing the two
 * would trade a useful rule for a loud one, which in practice means for a disabled one.
 *
 * ## Matching is on segments, not substrings
 *
 * `rating` is not `rate` and `evaluate` is not `value`. A substring match would report both, and the
 * first false positive of that shape is the one that teaches somebody to ignore the rule.
 */
final class MoneyColumnDictionary
{
    /** The artifact's file name under `resources/data`. */
    public const string ARTIFACT = 'money-columns.json';

    /** The artifact shape this build implements. */
    public const int SCHEMA_VERSION = 1;

    private static ?self $bundled = null;

    /**
     * @param  list<string>  $strong  terms that mean money on their own
     * @param  list<string>  $weak  terms that need a second signal
     */
    private function __construct(
        public readonly array $strong,
        public readonly array $weak,
    ) {}

    /**
     * @param  list<string>  $extra  project terms, treated as strong — a project naming its own
     *                               column knows what it holds
     * @param  list<string>  $ignore  terms this project does not want reported, removed from both
     *                                levels so an ignore cannot be defeated by the level it lands in
     */
    public static function bundled(array $extra = [], array $ignore = []): self
    {
        self::$bundled ??= self::fromFile(dirname(__DIR__, 3).'/resources/data/'.self::ARTIFACT);

        if ($extra === [] && $ignore === []) {
            return self::$bundled;
        }

        return self::$bundled->with($extra, $ignore);
    }

    /** Forget the memoized artifact — for tests that swap it. */
    public static function forgetBundled(): void
    {
        self::$bundled = null;
    }

    public static function fromFile(string $path): self
    {
        // Existence is checked BEFORE reading rather than inferred from a false return: a missing
        // file makes file_get_contents raise, and under Laravel's error handler that becomes an
        // ErrorException — which would leave this layer's own named failure unreachable.
        if (! is_file($path)) {
            throw new UnreadableMoneyDictionary($path, 'the file could not be read');
        }

        // Cast rather than a false-check: with the existence question already answered above, the
        // only way this returns false is an existing file the process may not read — and under
        // Laravel's error handler that raises before it can return anything. An arm nothing can
        // reach would read as covered while proving nothing; an unreadable file falls through to
        // the JSON failure below, which names the path just as clearly.
        $contents = (string) file_get_contents($path);

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($contents, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw new UnreadableMoneyDictionary($path, 'the file is not valid JSON: '.$error->getMessage());
        }

        $version = $decoded['schema_version'] ?? null;

        // A version mismatch is refused rather than read optimistically: a shape this build does not
        // implement, parsed as if it did, produces a dictionary that is quietly wrong — and a wrong
        // money heuristic is worse than none, because it is believed.
        if ($version !== self::SCHEMA_VERSION) {
            throw new UnreadableMoneyDictionary($path, sprintf(
                'schema_version %s is not the %d this build implements',
                is_scalar($version) ? (string) $version : '(missing)',
                self::SCHEMA_VERSION,
            ));
        }

        $strong = [];
        $weak = [];

        /** @var list<array<string, mixed>> $terms */
        $terms = is_array($decoded['terms'] ?? null) ? $decoded['terms'] : [];

        foreach ($terms as $entry) {
            $term = $entry['term'] ?? null;
            $confidence = $entry['confidence'] ?? null;

            if (! is_string($term) || $term === '') {
                throw new UnreadableMoneyDictionary($path, 'a term entry has no usable name');
            }

            match ($confidence) {
                'strong' => $strong[] = $term,
                'weak' => $weak[] = $term,
                default => throw new UnreadableMoneyDictionary($path, sprintf(
                    'the term "%s" has confidence %s; only "strong" and "weak" exist',
                    $term,
                    is_scalar($confidence) ? '"'.$confidence.'"' : '(missing)',
                )),
            };
        }

        if ($strong === []) {
            // An empty dictionary would make the rule silent while every test about it still passed.
            throw new UnreadableMoneyDictionary($path, 'the dictionary contains no strong terms at all');
        }

        return new self($strong, $weak);
    }

    /** Whether this name is money on its own. */
    public function isStrong(string $columnName): bool
    {
        return $this->matches($columnName, $this->strong);
    }

    /** Whether this name suggests money but needs a second signal before anything is reported. */
    public function isWeak(string $columnName): bool
    {
        return $this->matches($columnName, $this->weak);
    }

    /**
     * The project's own view: extra terms added as strong, ignored terms removed from both levels.
     *
     * An ignore removes from BOTH levels on purpose. Removing it from only the level it happens to
     * sit in today would mean a project's `ignore` silently stops working the day the term is
     * reclassified — which is the kind of failure nobody connects back to a config file.
     *
     * @param  list<string>  $extra
     * @param  list<string>  $ignore
     */
    private function with(array $extra, array $ignore): self
    {
        $ignored = $this->normalized($ignore);

        $strong = $this->without([...$this->strong, ...$this->normalized($extra)], $ignored);
        sort($strong);

        return new self($strong, $this->without($this->weak, $ignored));
    }

    /**
     * Terms lowercased and de-duplicated — the shape everything else compares against.
     *
     * @param  list<string>  $terms
     * @return list<string>
     */
    private function normalized(array $terms): array
    {
        $normalized = [];

        foreach ($terms as $term) {
            $lowered = mb_strtolower(trim($term));

            if ($lowered !== '' && ! in_array($lowered, $normalized, true)) {
                $normalized[] = $lowered;
            }
        }

        return $normalized;
    }

    /**
     * @param  list<string>  $terms
     * @param  list<string>  $ignored
     * @return list<string>
     */
    private function without(array $terms, array $ignored): array
    {
        $kept = [];

        foreach ($terms as $term) {
            if (! in_array($term, $ignored, true)) {
                $kept[] = $term;
            }
        }

        return $kept;
    }

    /**
     * Whether any term matches a whole underscore-separated segment of the name.
     *
     * The segmentation is shared with the privacy dictionary, which reads column names for a
     * different question and must agree with this one about what a name IS. The predicate is not
     * shared: this one keeps a multi-word term to a whole-name match on purpose, while the privacy
     * side allows a run of adjacent segments. Both are named at {@see ColumnNameSegments}.
     *
     * @param  list<string>  $terms
     */
    private function matches(string $columnName, array $terms): bool
    {
        return ColumnNameSegments::plain($columnName)->matchesWholeOrSegment($terms);
    }
}
