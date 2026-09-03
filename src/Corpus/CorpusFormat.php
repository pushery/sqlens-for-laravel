<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

/**
 * The shape a false-positive corpus collection has to have.
 *
 * ## Why the format is its own piece of work
 *
 * Every claim about SQLens' false-positive rate is a claim about a measurement, and a measurement
 * needs a ground truth that somebody wrote down before the run. Without a format there is no place
 * to write it down, so the number would be an assertion with a decimal point on it.
 *
 * This class is the format and nothing else: what a collection looks like, which manifest fields are
 * mandatory, and which three verdicts an expectation may carry. The LOADER that reads collections
 * and refuses an incomplete one is the corpus tickets; the measurement that classifies findings against
 * these expectations is the corpus tickets. Keeping them apart is what stops the loader from inventing a
 * second, slightly different idea of what a manifest is.
 *
 * ## The three-valued expectation is the load-bearing part
 *
 * `expected_undetermined` is a first-class verdict, not a shrug. A rule that honestly reports it
 * cannot run — no privilege, no catalog, a version outside its window — has done the right thing,
 * and counting that as a false positive would push the package toward guessing. It is the same
 * three-valuedness the findings themselves carry, held at the corpus layer so the measurement
 * cannot quietly flatten it to pass/fail.
 */
final readonly class CorpusFormat
{
    // Where a corpus lives is the CALLER's business, and deliberately not a constant here. This
    // class describes the FORMAT — which manifest fields are mandatory, which three verdicts an
    // expectation may carry. A path baked in beside them would tie the format to one repository's
    // layout, and the first consumer wanting to measure its own migrations would have to fork it.

    /**
     * The two provenance classes, kept apart in the LAYOUT rather than in a manifest field.
     *
     * A synthetic collection is derived from this package's own rule fixtures, so its ground truth
     * is known by construction. A real one is somebody else's migrations under a checked license,
     * and its ground truth was established by reading. Those are different kinds of evidence, and a
     * reader must be able to tell which a number came from without opening a manifest.
     *
     * @var list<string>
     */
    public const array CLASSES = ['synthetic', 'real'];

    /** The file naming a collection's origin and terms. */
    public const string MANIFEST = 'manifest.json';

    /** The file carrying the ground truth. */
    public const string EXPECTED = 'expected.json';

    /**
     * Every manifest field a collection must carry, with what its absence would cost.
     *
     * `license` is the one that makes this a hard failure rather than a warning: a corpus is other
     * people's code, and an unlicensed collection in a repository is a legal problem that a warning
     * in a log does not solve. The rest are what make a number reproducible six months later —
     * a measurement whose inputs nobody can identify is an anecdote.
     *
     * @var array<string, string> field => why it is mandatory
     */
    public const array REQUIRED_MANIFEST_FIELDS = [
        'name' => 'the collection has to be nameable in a report; an unnamed row is a number nobody can trace',
        'provenance' => 'where these migrations came from. A corpus whose origin is unrecorded cannot be re-collected, and cannot be checked for the one thing this package forbids: examples copied out of another tool documentation',
        'license' => 'the terms the collection is used under. Absent, this is a legal problem rather than a data-quality one, which is why it fails the suite instead of warning',
        'collected_on' => 'the date the collection was taken. Migrations age, and a rate measured against a 2019 corpus is a different claim from the same rate today',
        'engine' => 'which engine the collection targets. A PostgreSQL corpus measured against the MySQL rules would report a false-positive rate for rules that never ran',
        'laravel_version' => 'the framework the migrations were written for. The schema builder emits different SQL across majors, so the same migration is a different subject',
        'corpus_version' => 'the version of this collection, so a report can say which one it measured',
        'rule_catalog_hash' => 'the rule set the collection was last measured against. Without it a stale report reads exactly like a fresh one — the input the release gate needs in order to refuse a 1.0 whose rules moved after the last measurement',
    ];

    /**
     * The three verdicts a ground-truth entry may carry.
     *
     * @var list<string>
     */
    public const array EXPECTATION_CLASSES = ['expected_fail', 'expected_pass', 'expected_undetermined'];

    /**
     * What is wrong with a manifest, named one item at a time.
     *
     * A boolean would say a collection is invalid and leave whoever wrote it to guess which of eight
     * fields it was. Every message names the field AND the reason it exists, because a required
     * field whose purpose is unstated gets filled with a placeholder.
     *
     * @param  array<string, mixed>  $manifest
     * @return list<string>
     */
    public static function manifestViolations(array $manifest): array
    {
        $violations = [];

        foreach (self::REQUIRED_MANIFEST_FIELDS as $field => $why) {
            if (! array_key_exists($field, $manifest)) {
                $violations[] = "missing `{$field}` — {$why}";

                continue;
            }

            if (! is_string($manifest[$field]) || trim($manifest[$field]) === '') {
                $violations[] = "empty `{$field}` — {$why}";
            }
        }

        // An unknown field is a violation rather than a curiosity: a manifest that accepts anything
        // is a manifest in which a typo'd `license` silently means no license at all.
        foreach (array_keys($manifest) as $field) {
            if (! array_key_exists($field, self::REQUIRED_MANIFEST_FIELDS)) {
                $violations[] = "unknown field `{$field}` — the schema is closed, so a misspelled required field reads as a missing one rather than passing";
            }
        }

        sort($violations);

        return $violations;
    }

    /**
     * What is wrong with a ground-truth file.
     *
     * @param  array<mixed>  $expected
     * @return list<string>
     */
    public static function expectationViolations(array $expected): array
    {
        $violations = [];

        foreach ($expected as $index => $entry) {
            $where = "entry {$index}";

            if (! is_array($entry)) {
                $violations[] = "{$where} is not an object";

                continue;
            }

            if (! isset($entry['rule_id']) || ! is_string($entry['rule_id']) || trim($entry['rule_id']) === '') {
                // The one the ticket names by hand, because it is the one that produces a silent
                // pass: an expectation with no rule id matches nothing, so the finding it was
                // supposed to describe is simply never compared.
                $violations[] = "{$where} carries no `rule_id`, so it can never be matched against a finding and the case measures nothing";
            }

            if (! isset($entry['outcome']) || ! in_array($entry['outcome'], self::EXPECTATION_CLASSES, true)) {
                $violations[] = sprintf(
                    '%s has outcome `%s`, which is not one of %s. `expected_undetermined` is a real verdict rather than a shrug: a rule that honestly reports it cannot run has done the right thing, and counting that as a false positive would push the package toward guessing',
                    $where,
                    is_scalar($entry['outcome'] ?? null) ? (string) $entry['outcome'] : gettype($entry['outcome'] ?? null),
                    implode(', ', self::EXPECTATION_CLASSES),
                );
            }
        }

        sort($violations);

        return $violations;
    }

    /**
     * Every collection directory under the root, in a deterministic order.
     *
     * Sorted rather than left to the filesystem, because two machines walking a directory in
     * different orders would produce two different reports from one corpus — and a report whose
     * diff is noise is a report nobody reads.
     *
     * @return list<string> repo-relative paths
     */
    public static function collections(string $repositoryRoot, string $corpusRoot): array
    {
        $found = [];

        foreach (self::CLASSES as $class) {
            $directory = $repositoryRoot.'/'.$corpusRoot.'/'.$class;

            foreach ((array) glob($directory.'/*', GLOB_ONLYDIR) as $path) {
                $found[] = str_replace($repositoryRoot.'/', '', (string) $path);
            }
        }

        sort($found);

        return $found;
    }
}
