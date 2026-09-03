<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use JsonException;
use Pushery\SQLens\Exceptions\UnreadableDriftExcludes;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The versioned file that records which differences a project has decided to live with.
 *
 * ## It lives in the REPOSITORY, never in a database
 *
 * A decision about a schema belongs where decisions are reviewed. In the repository it arrives
 * through a pull request, carries an author and a date, and its removal is as visible as its
 * addition. In a table it would be a row somebody changed at 2am with no diff — and this package
 * writes to no database at all, which is a promise rather than a preference.
 *
 * ## The shape is merge-friendly on purpose
 *
 * One entry per line, sorted by identity. Two people adding an exclusion on the same day touch
 * different lines, and a git conflict — if one happens — is resolvable by reading it. A file sorted
 * by insertion order would reorder on every regeneration and make every diff unreadable.
 *
 * ## An unknown version is refused, not interpreted
 *
 * The version is explicit and mandatory. A file this build only half understands decides which
 * findings a project stops seeing, and reading the recognizable half of it is the worst available
 * answer: the run succeeds, the report looks clean, and the entries this build could not parse are
 * simply not applied.
 */
final readonly class DriftExcludeFile
{
    /** The format this build reads and writes. Bump it only with a migration path or a named refusal. */
    public const int VERSION = 1;

    /**
     * Where the accepted-differences file lives when a project has not said otherwise —
     * repository-relative, never absolute.
     *
     * Here rather than on a command, because TWO commands read this file: `sqlens:drift` judges it
     * and `sqlens:postdeploy --expect-shadow` honors it. A default living on one of them is a
     * default the other has to restate, and a restated constant is one that drifts — at which point
     * a difference a project accepted keeps coming back through the other command, which is the one
     * failure the shared comparison path exists to prevent.
     */
    public const string DEFAULT_PATH = 'sqlens-drift-excludes.json';

    /**
     * The configured path, resolved against the repository root — the ONE resolution both readers
     * make.
     *
     * The config value is repository-relative on purpose: an absolute one would put a decision log
     * outside the repository, where its changes are reviewed by nobody. A per-run override typed by
     * a person who can see where they are pointing is a different thing, and stays with the command
     * that offers the flag.
     */
    public static function configuredPath(?string $configured, string $basePath): string
    {
        return $basePath.'/'.(is_string($configured) && $configured !== '' ? $configured : self::DEFAULT_PATH);
    }

    /**
     * @param  list<DriftExcludeEntry>  $entries  sorted by identity
     */
    private function __construct(public string $path, public array $entries) {}

    /**
     * An empty set for a project that has no file — which is the normal state, not an error.
     *
     * A missing file means "nothing has been accepted yet", and that is a complete answer. Demanding
     * the file would make the first `sqlens:drift` run of every project fail on a file it could not
     * have written yet.
     */
    public static function absent(string $path): self
    {
        return new self($path, []);
    }

    /**
     * Read the file at a path, or an empty set when it is not there.
     *
     * @throws UnreadableDriftExcludes when the file exists and cannot be trusted
     */
    public static function read(string $path): self
    {
        if (! is_file($path)) {
            return self::absent($path);
        }

        $raw = @file_get_contents($path);

        // A failed read and a file that holds nothing are one condition here — see the factory for
        // why they are not two. Whitespace counts as nothing: a file holding a newline is as empty
        // as one holding no bytes, and reporting it as a JSON syntax error sends the reader looking
        // for a syntax that is not there.
        if ($raw === false || trim($raw) === '') {
            throw UnreadableDriftExcludes::yieldedNothing($path);
        }

        try {
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            throw UnreadableDriftExcludes::notJson($path, $error->getMessage());
        }

        if (! is_array($decoded) || array_is_list($decoded)) {
            throw UnreadableDriftExcludes::notAnObject($path, get_debug_type($decoded));
        }

        if (! array_key_exists('schema_version', $decoded)) {
            throw UnreadableDriftExcludes::missingVersion($path);
        }

        if ($decoded['schema_version'] !== self::VERSION) {
            throw UnreadableDriftExcludes::unsupportedVersion($path, $decoded['schema_version'], self::VERSION);
        }

        $entries = $decoded['entries'] ?? [];

        if (! is_array($entries) || ! array_is_list($entries)) {
            throw UnreadableDriftExcludes::entriesNotAList($path, get_debug_type($entries));
        }

        return new self($path, self::sorted(array_map(
            static fn (mixed $row, int $index): DriftExcludeEntry => self::entry($path, $index, $row),
            $entries,
            array_keys($entries),
        )));
    }

    /**
     * The file's own text, ready to write.
     *
     * `JSON_PRETTY_PRINT` and a trailing newline, because this file is read and edited by people —
     * and a one-line JSON document is one nobody can review in a diff.
     */
    public function contents(): string
    {
        return json_encode([
            'schema_version' => self::VERSION,
            'entries' => array_map(static fn (DriftExcludeEntry $entry): array => $entry->toArray(), $this->entries),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    }

    /**
     * The same set with these entries added, deduplicated by identity and sorted.
     *
     * EXISTING entries win. A regeneration must never overwrite a reason somebody wrote with the
     * placeholder a machine writes — that would quietly erase the one field this file exists
     * for, and it would do it on the run that was supposed to be housekeeping.
     *
     * @param  list<DriftExcludeEntry>  $additions
     */
    public function with(array $additions): self
    {
        $byKey = [];

        foreach ([...$this->entries, ...$additions] as $entry) {
            $byKey[$entry->sortKey()] ??= $entry;
        }

        return new self($this->path, self::sorted(array_values($byKey)));
    }

    /**
     * @param  list<DriftExcludeEntry>  $entries
     * @return list<DriftExcludeEntry>
     */
    private static function sorted(array $entries): array
    {
        usort($entries, static fn (DriftExcludeEntry $a, DriftExcludeEntry $b): int => $a->sortKey() <=> $b->sortKey());

        return $entries;
    }

    private static function entry(string $path, int $index, mixed $row): DriftExcludeEntry
    {
        if (! is_array($row) || array_is_list($row)) {
            throw UnreadableDriftExcludes::malformedEntry($path, $index, 'it is '.get_debug_type($row).' rather than an object');
        }

        $type = SchemaObjectType::tryFrom(is_string($row['type'] ?? null) ? $row['type'] : '');

        if (! $type instanceof SchemaObjectType) {
            throw UnreadableDriftExcludes::malformedEntry($path, $index, 'its "type" is not an object type SQLens compares');
        }

        $name = $row['name'] ?? null;

        if (! is_string($name) || $name === '') {
            throw UnreadableDriftExcludes::malformedEntry($path, $index, 'its "name" is missing or empty');
        }

        $attribute = $row['attribute'] ?? null;

        if ($attribute !== null && (! is_string($attribute) || $attribute === '')) {
            throw UnreadableDriftExcludes::malformedEntry($path, $index, 'its "attribute" is neither null nor a name');
        }

        $reason = $row['reason'] ?? null;

        // Three ways to have no reason, and all three are the same fact.
        //
        // Whitespace is trimmed first, because " " passes `is_string` and an empty-looking field is
        // exactly what somebody types to get past a validator. And the generator's own placeholder
        // is refused BY NAME — that is what makes `--update-excludes` produce a file a person must
        // edit rather than one they can commit and forget.
        if (! is_string($reason) || trim($reason) === '' || trim($reason) === DriftExcludes::UNEXPLAINED) {
            throw UnreadableDriftExcludes::entryWithoutReason($path, $index, $type->value.' `'.$name.'`');
        }

        return new DriftExcludeEntry($type, $name, $attribute, $reason);
    }
}
