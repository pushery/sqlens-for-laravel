<?php

declare(strict_types=1);

namespace Pushery\SQLens\Corpus;

use JsonException;

/**
 * Reads corpus collections, and REFUSES an incomplete one.
 *
 * ## The whole design is one decision, made six times
 *
 * Every branch below that could have been a skip is a throw. The reason is arithmetic rather than
 * strictness: the measurement this feeds computes a false-positive RATE. A collection that dropped
 * out silently would shrink both halves of that fraction and leave the result looking entirely
 * normal — a plausible number over a corpus nobody chose. Worse, the failure modes all bias the
 * same way: a missing expectation file, a truncated one, a collection with no migrations, each
 * removes findings that might have been wrong and none that were right.
 *
 * So there is no default expectation, no partial load, and no "assume it passes".
 *
 * ## Why it takes a root instead of knowing one
 *
 * The corpus lives under a path this class does not need to know, and the tests that prove the six
 * refusals need to build broken collections somewhere harmless. A loader that knew its own root
 * would have to be tested against the real corpus, which means either shipping deliberately broken
 * collections in the repository or not testing the refusals at all.
 *
 * ## Where the boundary to the measurement runs
 *
 * This class reads FILES and hands back data. The classification and metrics layer (the corpus tickets)
 * takes that data and never touches a filesystem, which is what lets it live in `src/` without
 * shipping corpus machinery to consumers. Anything here that started resolving findings would have
 * put a test-fixture reader on the far side of that line.
 */
final readonly class CorpusLoader
{
    /**
     * Every collection under the root, validated, in a deterministic order.
     *
     * @return list<CorpusCollection>
     *
     * @throws CorpusLoadFailure
     */
    public static function load(string $repositoryRoot, string $corpusRoot): array
    {
        $collections = [];

        foreach (CorpusFormat::collections($repositoryRoot, $corpusRoot) as $relative) {
            $collections[] = self::one($repositoryRoot, $corpusRoot, $relative);
        }

        return $collections;
    }

    /**
     * @throws CorpusLoadFailure
     */
    private static function one(string $repositoryRoot, string $corpusRoot, string $relative): CorpusCollection
    {
        $directory = $repositoryRoot.'/'.$relative;

        $manifestPath = $relative.'/'.CorpusFormat::MANIFEST;
        $expectedPath = $relative.'/'.CorpusFormat::EXPECTED;

        if (! is_file($repositoryRoot.'/'.$manifestPath)) {
            throw CorpusLoadFailure::missingManifest($relative, $manifestPath);
        }

        if (! is_file($repositoryRoot.'/'.$expectedPath)) {
            throw CorpusLoadFailure::missingExpectations($relative, $expectedPath);
        }

        /** @var array<string, string> $manifest */
        $manifest = self::json($relative, $manifestPath, $repositoryRoot.'/'.$manifestPath);
        /** @var list<array{rule_id: string, outcome: string}> $expectations */
        $expectations = self::json($relative, $expectedPath, $repositoryRoot.'/'.$expectedPath);

        $manifestViolations = CorpusFormat::manifestViolations($manifest);

        if ($manifestViolations !== []) {
            throw CorpusLoadFailure::invalidManifest($relative, $manifestViolations);
        }

        $expectationViolations = CorpusFormat::expectationViolations($expectations);

        if ($expectationViolations !== []) {
            throw CorpusLoadFailure::invalidExpectations($relative, $expectationViolations);
        }

        $migrations = self::migrations($repositoryRoot, $directory);

        if ($migrations === []) {
            throw CorpusLoadFailure::noMigrations($relative);
        }

        return new CorpusCollection(
            path: $relative,
            // Read off the LAYOUT rather than out of the manifest. A field could say `real` about a
            // collection sitting in `synthetic/`, and the directory is the thing a reader sees.
            provenance: self::provenanceOf($corpusRoot, $relative),
            manifest: $manifest,
            expectations: $expectations,
            migrations: $migrations,
        );
    }

    /**
     * @return array<array-key, mixed>
     *
     * @throws CorpusLoadFailure
     */
    private static function json(string $collection, string $relative, string $absolute): array
    {
        try {
            $decoded = json_decode((string) file_get_contents($absolute), true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw CorpusLoadFailure::unreadableJson($collection, $relative, $error->getMessage());
        }

        if (! is_array($decoded)) {
            throw CorpusLoadFailure::unreadableJson($collection, $relative, 'the file decodes to '.gettype($decoded).' rather than to a structure');
        }

        return $decoded;
    }

    /**
     * The migration files of a collection, sorted.
     *
     * Sorted rather than left to `glob()`'s platform order, because the measurement quotes its own
     * ground set and two machines listing one collection differently would produce two reports that
     * diff against each other for no reason. A diff that is noise is a diff nobody reads.
     *
     * @return list<string>
     */
    private static function migrations(string $repositoryRoot, string $directory): array
    {
        $files = [];

        foreach ((array) glob($directory.'/*.php') as $path) {
            $files[] = str_replace($repositoryRoot.'/', '', (string) $path);
        }

        sort($files);

        return $files;
    }

    /**
     * `synthetic` or `real`, from the directory the collection sits in.
     *
     * READ off the path rather than searched for among the known classes, and the difference is a
     * branch that could never be taken. A loop over `CorpusFormat::CLASSES` needs an answer for the
     * case where none matches — and `collections()` only ever walks those two directories, so that
     * answer was unreachable code carrying a comment explaining why it was unreachable. The segment
     * after the root IS the class, so there is nothing to decide.
     */
    private static function provenanceOf(string $corpusRoot, string $relative): string
    {
        $withinCorpus = mb_substr($relative, mb_strlen($corpusRoot) + 1);

        return explode('/', $withinCorpus)[0];
    }
}
