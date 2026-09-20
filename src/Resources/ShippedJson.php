<?php

declare(strict_types=1);

namespace Pushery\SQLens\Resources;

use JsonException;
use Pushery\SQLens\Exceptions\UnreadableShippedArtifact;
use Pushery\SQLens\Tests\Support\BundledLoaderPolicy;

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
 * Here it is made once, and {@see BundledLoaderPolicy} can then check
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
     * `$requiredKey`, when given, must be present AND be an array. That check belongs here rather than
     * in each caller: a file that parses but carries no entries list is the same broken installation as
     * one that does not parse, and a loader that checked only the parse would hand back a valid-looking
     * empty register — the exact answer this class exists to prevent.
     *
     * @return array<array-key, mixed>
     */
    public static function decode(string $path, ?string $requiredKey = null): array
    {
        // ⚠️ ONE BRANCH, NOT TWO, AND THE REASON IS COVERAGE RATHER THAN BREVITY. This read used to be
        // guarded by `is_file()` first and `$raw === false` second, which reads well and left a line no
        // run can enter: a path that passes `is_file()` and then fails to READ needs a permission setup
        // that is not portable to a CI container. Gate 2866 named it — `uncovered
        // src/Resources/ShippedJson.php: 53` — and the honest answer to an unreachable branch is to not
        // have one, rather than to chmod a fixture and hope the container is not root.
        //
        // The two messages survive, because they send an operator on different errands: "not there" means
        // reinstall, "could not be read" means look at permissions. They are chosen inline, on ONE line,
        // since a multi-line ternary has an else-line coverage never marks either.
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

        if ($requiredKey !== null && ! is_array($decoded[$requiredKey] ?? null)) {
            throw new UnreadableShippedArtifact($path, sprintf('the file carries no "%s" list', $requiredKey));
        }

        return $decoded;
    }
}
