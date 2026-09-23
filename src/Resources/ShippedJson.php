<?php

declare(strict_types=1);

namespace Pushery\SQLens\Resources;

use JsonException;
use Pushery\SQLens\Exceptions\UnreadableShippedArtifact;

/**
 * Reads a JSON file this package SHIPS, and refuses rather than degrading.
 *
 * ## Why one class instead of the same eight lines in each loader
 *
 * Three bundled registers answered a read error with an EMPTY base set while seven answered with a
 * named exception, so the policy existed and was simply not followed. Eight lines copied into each
 * loader would leave the same thing true of the ninth: the reason those three drifted is that every
 * loader got to decide for itself, and a decision made ten times is a decision made differently.
 *
 * Here it is made once, and `tests/Feature/Architecture/BundledArtifactPolicyTest` can then check
 * that every shipped path goes through it instead of hand-rolling a fallback.
 *
 * ## Why it takes a path
 *
 * So it can be armed. The loaders read a path they do not choose, which is exactly why they must be
 * strict — but it also means no test can put their artifact into a broken state without corrupting
 * the repository's own files to do it. A path parameter moves the proof somewhere a temp file is
 * enough, and it is the seam the three loaders' own `fromFile()` methods already have for the same
 * reason.
 */
final readonly class ShippedJson
{
    /**
     * The decoded artifact, or an exception naming what is wrong with it.
     *
     * `$requiredKey`, when given, must be present, be an array, and NOT BE EMPTY. That check belongs
     * here rather than in each caller: a file that parses but carries no entries list is the same
     * broken installation as one that does not parse, and a loader that checked only the parse would
     * hand back a valid-looking empty register — the exact answer this class exists to prevent.
     *
     * An empty required list is refused like a missing one: "an empty register would make the rules
     * that read it silently correct about every server, which is a pass and not an undetermined" holds
     * for `{"entries": []}` exactly as for a missing `entries` key.
     *
     * It is tied to `$requiredKey` rather than applied to every read, and the distinction is
     * load-bearing. A caller that names a required key has already said it cannot work without that
     * list. The three callers that name none — the baseline's emittable ids and the two suppression
     * sources — are correct to accept an empty file: nothing accepted and nothing suppressed both mean
     * everything is reported, which is the loud direction. Refusing them would turn a legitimate state
     * into a broken installation.
     *
     * @return array<array-key, mixed>
     */
    public static function decode(string $path, ?string $requiredKey = null): array
    {
        // One read, one branch. A path that passes `is_file()` and then fails to read needs a
        // permission setup no portable environment reproduces, so it gets no branch of its own; the
        // read decides, and the message is chosen after it.
        //
        // The two messages send an operator on different errands: "not there" means reinstall,
        // "could not be read" means look at permissions.
        $raw = @file_get_contents($path);

        if ($raw === false) {
            throw new UnreadableShippedArtifact($path, is_file($path) ? 'the file could not be read' : 'the file is not there');
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw new UnreadableShippedArtifact($path, 'the file is not valid JSON: '.$error->getMessage());
        }

        if (! is_array($decoded)) {
            throw new UnreadableShippedArtifact($path, 'the file is valid JSON but not an object');
        }

        if ($requiredKey !== null) {
            $list = $decoded[$requiredKey] ?? null;

            // One message for both shapes, because they are one broken installation and send an
            // operator on the same errand. Splitting them would suggest an empty list is a milder
            // state than a missing one, and the whole point is that it is not.
            if (! is_array($list) || $list === []) {
                throw new UnreadableShippedArtifact($path, sprintf('the file carries no "%s" list', $requiredKey));
            }
        }

        return $decoded;
    }
}
