<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use JsonException;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Exceptions\UnreadableBaseline;
use Pushery\SQLens\Severity\Severity;

/**
 * Writes and reads the baseline file.
 *
 * The layout is chosen for merges, not for looks: the version sits alone on the
 * first field, and every entry is exactly ONE line with a fixed key order. That
 * way adding or removing an accepted finding is a one-line diff instead of a
 * six-line reflow, and two people accepting different findings in the same week
 * do not collide. Pretty-printing the whole document would spread one entry over
 * six lines and turn every change into a conflict magnet.
 *
 * The file carries NO timestamp and NO aggregate counts. Either would mutate on
 * every write and make the second run of an unchanged project produce a diff,
 * which is the fastest way to teach people to stop reading the diff.
 */
final readonly class BaselineSerializer
{
    /** Two spaces, matching the shipped config and the JSON envelope. */
    private const string INDENT = '  ';

    /** Serialize a baseline to the exact bytes written to disk, trailing newline included. */
    public function serialize(BaselineFile $baseline): string
    {
        $lines = [
            '{',
            self::INDENT.'"'.BaselineSchema::VERSION_KEY.'": '.BaselineSchema::VERSION.',',
        ];

        if ($baseline->isEmpty()) {
            $lines[] = self::INDENT.'"'.BaselineSchema::ENTRIES_KEY.'": []';
            $lines[] = '}';

            return implode("\n", $lines)."\n";
        }

        $lines[] = self::INDENT.'"'.BaselineSchema::ENTRIES_KEY.'": [';

        $last = count($baseline->entries) - 1;

        foreach ($baseline->entries as $index => $entry) {
            $lines[] = self::INDENT.self::INDENT.$this->encodeEntry($entry).($index === $last ? '' : ',');
        }

        $lines[] = self::INDENT.']';
        $lines[] = '}';

        return implode("\n", $lines)."\n";
    }

    /**
     * Read a baseline back. `$path` only ever appears in messages, so a failure
     * names the file the user has to fix.
     *
     * @throws UnreadableBaseline
     */
    public function deserialize(string $json, string $path): BaselineFile
    {
        try {
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $failure) {
            throw UnreadableBaseline::invalidJson($path, $failure->getMessage());
        }

        return BaselineFile::of(array_map(
            fn (mixed $raw, int $index): BaselineEntry => $this->decodeEntry($raw, $index, $path),
            $entries = BaselineSchema::readEntries($decoded, $path),
            array_keys($entries),
        ));
    }

    /** One entry, compact, with the key order fixed by BaselineEntry::toArray(). */
    private function encodeEntry(BaselineEntry $entry): string
    {
        // Slashes and unicode stay unescaped so a path or an identifier reads the
        // way it was written; the flags are explicit so the bytes cannot drift with
        // a php.ini default.
        return json_encode($entry->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /** @throws UnreadableBaseline */
    private function decodeEntry(mixed $raw, int $index, string $path): BaselineEntry
    {
        if (! is_array($raw) || array_is_list($raw)) {
            throw UnreadableBaseline::entryNotAnObject($path, $index, get_debug_type($raw));
        }

        $expected = array_keys(BaselineEntry::FIELDS);

        foreach ($expected as $field) {
            if (! array_key_exists($field, $raw)) {
                throw UnreadableBaseline::entryMissingField($path, $index, $field);
            }
        }

        foreach (array_keys($raw) as $field) {
            if (! in_array((string) $field, $expected, true)) {
                throw UnreadableBaseline::entryUnknownField($path, $index, (string) $field, implode(', ', $expected));
            }
        }

        return new BaselineEntry(
            $this->fingerprint($raw['fingerprint'], $index, $path),
            $this->ordinal($raw['ordinal'], $index, $path),
            $this->text($raw['rule_id'], 'rule_id', $index, $path),
            $this->text($raw['subject'], 'subject', $index, $path),
            $this->category($raw['category'], $index, $path),
            $this->severity($raw['severity'], $index, $path),
        );
    }

    /**
     * The category, refused rather than defaulted when it is not one this build knows.
     *
     * A default here would be the quiet kind of wrong: an unrecognized category would become
     * `safety`, and a security entry would then be judged on the level axis — which is exactly the
     * confusion the two axes exist to prevent, arriving through a typo in a file somebody hand-edited.
     *
     * @throws UnreadableBaseline
     */
    private function category(mixed $value, int $index, string $path): Category
    {
        $category = is_string($value) ? Category::tryFrom($value) : null;

        if (! $category instanceof Category) {
            throw UnreadableBaseline::entryFieldOutOfShape(
                $path,
                $index,
                'category',
                'one of: '.implode(', ', array_map(static fn (Category $case): string => $case->value, Category::cases())),
                get_debug_type($value),
            );
        }

        return $category;
    }

    /**
     * The severity, or null — and null is a VALUE here, not a missing field.
     *
     * Outside the severity-gated categories there is no risk level to record, so the field is
     * written as null rather than omitted. That makes null legal and a wrong string illegal, which
     * is the distinction a hand-edited file needs.
     *
     * @throws UnreadableBaseline
     */
    private function severity(mixed $value, int $index, string $path): ?Severity
    {
        if ($value === null) {
            return null;
        }

        $severity = is_string($value) ? Severity::tryFrom($value) : null;

        if (! $severity instanceof Severity) {
            throw UnreadableBaseline::entryFieldOutOfShape(
                $path,
                $index,
                'severity',
                'one of: '.implode(', ', array_map(static fn (Severity $case): string => $case->value, Severity::cases())).', or null',
                get_debug_type($value),
            );
        }

        return $severity;
    }

    /** @throws UnreadableBaseline */
    private function fingerprint(mixed $value, int $index, string $path): FindingFingerprint
    {
        // A truncated or hand-edited fingerprint would match nothing, which reads
        // exactly like "this finding is new" and would quietly un-suppress it.
        $fingerprint = is_string($value) ? FindingFingerprint::fromStored($value) : null;

        return $fingerprint ?? throw UnreadableBaseline::entryFieldOutOfShape(
            $path,
            $index,
            'fingerprint',
            'a 64-character lowercase hex digest',
            get_debug_type($value),
        );
    }

    /** @throws UnreadableBaseline */
    private function ordinal(mixed $value, int $index, string $path): int
    {
        return is_int($value) && $value >= 0
            ? $value
            : throw UnreadableBaseline::entryFieldOutOfShape($path, $index, 'ordinal', 'a non-negative integer', get_debug_type($value));
    }

    /** @throws UnreadableBaseline */
    private function text(mixed $value, string $field, int $index, string $path): string
    {
        return is_string($value) && $value !== ''
            ? $value
            : throw UnreadableBaseline::entryFieldOutOfShape($path, $index, $field, 'a non-empty string', get_debug_type($value));
    }
}
