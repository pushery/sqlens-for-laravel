<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use Pushery\SQLens\Exceptions\UnreadableBaseline;

/**
 * The versioned shape of a baseline file, and the gate every read passes through.
 *
 * A baseline decides which findings stay hidden, so a file this build only half
 * understands must never be read anyway. The version is therefore explicit and
 * mandatory: a missing field is an error rather than an assumption, a newer
 * version stops the run instead of being partially honored, and an older version
 * is either migrated on a tested path or rejected by name — never read on the
 * hope that the parts we recognize are the parts that matter.
 *
 * Unknown top-level fields are reported for the same reason. They come from a
 * build that knew something this one does not; dropping them silently could
 * change which findings are suppressed without anyone seeing it.
 */
final readonly class BaselineSchema
{
    /**
     * The baseline format this build reads and writes. Bump it only together with
     * a migration path (or a named rejection) for every version below it.
     */
    public const int VERSION = 2;

    /** The mandatory root field carrying the format version. */
    public const string VERSION_KEY = 'schema_version';

    /** The root field holding the recorded entries. */
    public const string ENTRIES_KEY = 'entries';

    /**
     * Every field the root object may carry — nothing else is tolerated.
     *
     * @var list<string>
     */
    public const array ROOT_KEYS = [self::VERSION_KEY, self::ENTRIES_KEY];

    /**
     * Check a decoded baseline root and hand back its entries, or fail by name.
     * `$path` only ever appears in messages, so a user knows WHICH file to fix.
     *
     * @return list<mixed> the raw entries, whose shape the serializer validates
     *
     * @throws UnreadableBaseline
     */
    public static function readEntries(mixed $decoded, string $path): array
    {
        if (! is_array($decoded) || array_is_list($decoded)) {
            throw UnreadableBaseline::notAnObject($path, get_debug_type($decoded));
        }

        self::assertVersion($decoded, $path);
        self::assertNoUnknownRootFields($decoded, $path);

        if (! array_key_exists(self::ENTRIES_KEY, $decoded)) {
            throw UnreadableBaseline::missingRootField($path, self::ENTRIES_KEY);
        }

        $entries = $decoded[self::ENTRIES_KEY];

        if (! is_array($entries) || ! array_is_list($entries)) {
            throw UnreadableBaseline::entriesNotAList($path, get_debug_type($entries));
        }

        return $entries;
    }

    /**
     * The root of a freshly written baseline, version field first.
     *
     * @param  list<mixed>  $entries
     * @return array{schema_version: int, entries: list<mixed>}
     */
    public static function root(array $entries): array
    {
        return [
            self::VERSION_KEY => self::VERSION,
            self::ENTRIES_KEY => $entries,
        ];
    }

    /**
     * @param  array<array-key, mixed>  $decoded
     *
     * @throws UnreadableBaseline
     */
    private static function assertVersion(array $decoded, string $path): void
    {
        if (! array_key_exists(self::VERSION_KEY, $decoded)) {
            throw UnreadableBaseline::missingVersion($path, self::VERSION_KEY);
        }

        $version = $decoded[self::VERSION_KEY];

        // A string "1" is not a version: it is a hand-edited or hand-generated file,
        // and guessing what its author meant is exactly the assumption this refuses.
        if (! is_int($version)) {
            throw UnreadableBaseline::versionNotAnInteger($path, self::VERSION_KEY, get_debug_type($version));
        }

        if ($version > self::VERSION) {
            throw UnreadableBaseline::writtenByNewerVersion($path, $version, self::VERSION);
        }

        // Version 1 shipped, and there is deliberately no silent migration from it. A v1 entry
        // carries no category, so reading one would mean GUESSING which axis its author accepted —
        // and the wrong guess suppresses a critical security finding under a level entry's name.
        // Regenerating is cheap and the command is named in the message; guessing is not.
        if ($version < self::VERSION) {
            throw UnreadableBaseline::versionNoLongerRead($path, $version, self::VERSION);
        }
    }

    /**
     * @param  array<array-key, mixed>  $decoded
     *
     * @throws UnreadableBaseline
     */
    private static function assertNoUnknownRootFields(array $decoded, string $path): void
    {
        $unknown = [];

        foreach (array_keys($decoded) as $key) {
            if (! in_array((string) $key, self::ROOT_KEYS, true)) {
                $unknown[] = (string) $key;
            }
        }

        if ($unknown !== []) {
            throw UnreadableBaseline::unknownRootFields($path, $unknown, implode(', ', self::ROOT_KEYS));
        }
    }
}
