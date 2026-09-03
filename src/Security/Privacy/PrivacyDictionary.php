<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use JsonException;
use Pushery\SQLens\Catalog\Columns\ColumnNameSegments;

/**
 * The column-name terms that suggest a column holds personal data — read from data, never hard-coded.
 *
 * A name heuristic written as a regex inside a rule is a heuristic nobody can review: a diff shows a
 * changed pattern rather than a changed term. As a sorted artifact it reviews like a list, merges
 * like a list, and a project can extend it without forking the package.
 *
 * ## The seven languages are about the DATABASE, not about this package
 *
 * This is the confusion worth heading off, because the repository rule sitting next to it points the
 * other way: SQLens ships exactly one locale, `en`, and a second `lang/` directory turns a test red.
 * That rule is about what this package SAYS. This artifact is about what a schema is CALLED — a
 * German shop names a column `geburtsdatum` whatever language the report comes back in, and a
 * dictionary that only knew English would simply not see it.
 *
 * So there is no contradiction to resolve here, and nothing about this file argues for translating
 * any output.
 *
 * ## It is a name heuristic, and says so
 *
 * It never reads a value. A column called `iban` may hold a label and a column called `notes` may
 * hold a diagnosis, and neither is knowable from the catalog. The honest consequence is that the
 * findings built on this stay low — the point is to raise a question with somebody who can answer
 * it, not to assert an answer this package cannot have.
 */
final class PrivacyDictionary
{
    /** The artifact's file name under `resources/data`. */
    public const string ARTIFACT = 'privacy-dictionary.json';

    /** The artifact shape this build implements. */
    public const int SCHEMA_VERSION = 1;

    private static ?self $bundled = null;

    /**
     * @param  array<string, string>  $groupOf  term => group id
     * @param  array<string, string>  $signalOf  group id => `strong` or `weak`
     */
    private function __construct(
        private readonly array $groupOf,
        private readonly array $signalOf,
    ) {}

    /**
     * @param  list<string>  $extra  project terms, merged rather than replacing — a project naming
     *                               its own column knows what it holds
     */
    public static function bundled(array $extra = []): self
    {
        self::$bundled ??= self::fromFile(dirname(__DIR__, 3).'/resources/data/'.self::ARTIFACT);

        return $extra === [] ? self::$bundled : self::$bundled->with($extra);
    }

    /** Drops the memoized copy — for tests that write their own artifact. */
    public static function forgetBundled(): void
    {
        self::$bundled = null;
    }

    /**
     * A dictionary read from a project's own file, with the project's extra terms merged in.
     *
     * The `$extra` parameter is not decoration. `sqlens.security.privacy.extra_terms` and
     * `…privacy.dictionary` are two independent config keys, and a reading that honored the first
     * only for the BUNDLED dictionary would silently drop every extra term the moment a project
     * pointed at a file of its own — a config the user believes in and the tool ignores.
     *
     * @param  list<string>  $extra
     *
     * @throws UnreadablePrivacyDictionary
     */
    public static function fromFile(string $path, array $extra = []): self
    {
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw new UnreadablePrivacyDictionary($path, 'the file could not be read');
        }

        try {
            /** @var mixed $decoded */
            $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new UnreadablePrivacyDictionary($path, 'the file is not valid JSON: '.$e->getMessage());
        }

        if (! is_array($decoded)) {
            throw new UnreadablePrivacyDictionary($path, 'the file does not decode to an object');
        }

        $version = $decoded['schema_version'] ?? null;

        // Refused rather than read optimistically, on the same terms the money dictionary states: a
        // shape this build does not implement, parsed as if it did, produces a dictionary that is
        // quietly wrong — and a wrong heuristic is worse than none, because it is believed.
        if ($version !== self::SCHEMA_VERSION) {
            throw new UnreadablePrivacyDictionary($path, sprintf(
                'schema_version %s is not the %d this build implements',
                is_scalar($version) ? (string) $version : '(missing)',
                self::SCHEMA_VERSION,
            ));
        }

        $signalOf = [];

        foreach (is_array($decoded['groups'] ?? null) ? $decoded['groups'] : [] as $id => $group) {
            $signal = is_array($group) ? ($group['signal'] ?? null) : null;

            if (is_string($id) && ($signal === 'strong' || $signal === 'weak')) {
                $signalOf[$id] = $signal;
            }
        }

        $groupOf = [];

        foreach (is_array($decoded['terms'] ?? null) ? $decoded['terms'] : [] as $row) {
            if (! is_array($row)) {
                continue;
            }

            $term = $row['term'] ?? null;
            $group = $row['group'] ?? null;

            if (is_string($term) && $term !== '' && is_string($group) && isset($signalOf[$group])) {
                $groupOf[mb_strtolower($term)] = $group;
            }
        }

        if ($groupOf === []) {
            // An empty dictionary would make every privacy rule silent while every test about it
            // still passed — the exact shape of failure this package refuses to ship.
            throw new UnreadablePrivacyDictionary($path, 'the dictionary contains no usable terms at all');
        }

        return new self($groupOf, $signalOf)->with($extra);
    }

    /** Whether this column name matches any term at all. */
    public function matches(string $columnName): bool
    {
        return $this->groupFor($columnName) !== null;
    }

    /** The term group this column name matched, or null when it matched nothing. */
    public function groupFor(string $columnName): ?string
    {
        $segments = ColumnNameSegments::folded($columnName);

        // Sorted so two runs over one schema agree on WHICH group a name that matches several is
        // reported under. Without it the answer would follow the artifact's row order, which is a
        // determinism bug waiting for somebody to re-sort the file.
        $groups = array_values(array_unique(array_values($this->groupOf)));
        sort($groups);

        foreach ($groups as $group) {
            $terms = array_keys(array_filter($this->groupOf, static fn (string $g): bool => $g === $group));

            if ($segments->matchesWholeOrRun($terms)) {
                return $group;
            }
        }

        return null;
    }

    /**
     * `strong` or `weak` for a matched name, or null when nothing matched.
     *
     * The split decides how loud the finding is, and it is the artifact's call rather than the
     * rule's: `iban` means one thing, while `religion` is also an ordinary word in a CMS.
     */
    public function signalFor(string $columnName): ?string
    {
        $group = $this->groupFor($columnName);

        return $group === null ? null : ($this->signalOf[$group] ?? null);
    }

    /**
     * A project's own view: extra terms merged in, never replacing the bundled ones.
     *
     * They join the `identifiers` group, which is the only honest place for them — a project adding
     * a term knows the column is an identifier of some kind, and guessing a narrower group from the
     * word would be this package inventing a fact.
     *
     * @param  list<string>  $extra
     */
    private function with(array $extra): self
    {
        $groupOf = $this->groupOf;

        foreach ($extra as $term) {
            $lowered = mb_strtolower(trim($term));

            if ($lowered !== '') {
                $groupOf[$lowered] = 'identifiers';
            }
        }

        return new self($groupOf, $this->signalOf);
    }
}
