<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

use RuntimeException;

/**
 * A corpus collection that could not be loaded.
 *
 * ## Why this is an exception and not a skipped collection
 *
 * The measurement it feeds computes a false-positive RATE, which is a fraction. A collection that
 * silently dropped out would leave both halves of that fraction smaller and the result unchanged in
 * shape — a perfectly plausible number computed over a corpus nobody chose. That is the "silent
 * green" this package refuses everywhere, arriving through arithmetic rather than through a verdict.
 *
 * So an unloadable collection stops the run and says which one and why. There is no default
 * expectation, no partial load, and no "assume it passes": each of those turns a broken collection
 * into evidence of quality.
 *
 * Every constructor below names the COLLECTION and the DEFECT, because a loader that answers
 * "invalid corpus" sends whoever wrote it to read four files.
 */
final class CorpusLoadFailure extends RuntimeException
{
    public static function missingExpectations(string $collection, string $path): self
    {
        return new self(sprintf(
            'The corpus collection `%s` has no ground truth: `%s` is missing. Without it every '
            .'finding the rule set produces here would be unclassifiable, and a collection whose '
            .'findings cannot be classified must not be counted as one where nothing went wrong.',
            $collection,
            $path,
        ));
    }

    public static function missingManifest(string $collection, string $path): self
    {
        return new self(sprintf(
            'The corpus collection `%s` has no manifest: `%s` is missing. The manifest carries the '
            .'license the collection is used under and the rule-catalog hash it was last measured '
            .'against — the first is a legal question, the second is what stops a stale measurement '
            .'from reading like a fresh one.',
            $collection,
            $path,
        ));
    }

    /** @param  list<string>  $violations */
    public static function invalidManifest(string $collection, array $violations): self
    {
        return new self(sprintf(
            "The manifest of corpus collection `%s` is not usable:\n  - %s",
            $collection,
            implode("\n  - ", $violations),
        ));
    }

    /** @param  list<string>  $violations */
    public static function invalidExpectations(string $collection, array $violations): self
    {
        return new self(sprintf(
            "The ground truth of corpus collection `%s` is not usable:\n  - %s",
            $collection,
            implode("\n  - ", $violations),
        ));
    }

    public static function noMigrations(string $collection): self
    {
        return new self(sprintf(
            'The corpus collection `%s` holds no migration file at all. It would contribute zero '
            .'findings and zero expectations, so it would neither raise nor lower the measured rate '
            .'— an empty collection is indistinguishable from a flawless one, and only one of those '
            .'is worth shipping a number about.',
            $collection,
        ));
    }

    public static function unreadableJson(string $collection, string $path, string $reason): self
    {
        return new self(sprintf(
            'The corpus collection `%s` has a file the loader could not read as JSON: `%s` (%s). '
            .'Reported rather than skipped, because a truncated expectation file parses as fewer '
            .'expectations rather than as an error, and fewer expectations is a better-looking rate.',
            $collection,
            $path,
            $reason,
        ));
    }
}
