<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

/**
 * Renders a loaded matrix back to its ONE canonical on-disk form, so the data file stays cleanly
 * diffable as it grows: entries sorted by id, conditions and sources sorted within each entry,
 * object keys always in the same order, pretty-printed with a trailing newline. Change one entry
 * and the git diff touches only that entry's lines — never a neighbor reshuffled by an editor.
 *
 * Determinism is the whole point, so sorting is byte comparison ({@see strcmp}), never a
 * locale-aware or numeric-string collation: the same matrix serializes to the same bytes on any
 * PHP build under any locale. It emits from the typed matrix rather than shuffling raw JSON, so
 * the key order is fixed in code and cannot drift.
 */
final readonly class MatrixSerializer
{
    public function serialize(OnlineDdlMatrix $matrix): string
    {
        $entries = $matrix->all();
        usort($entries, static fn (MatrixEntry $a, MatrixEntry $b): int => strcmp($a->id, $b->id));

        $data = [
            'schema_version' => OnlineDdlMatrix::SCHEMA_VERSION,
            'reference_server' => $matrix->referenceServer,
            'about' => $matrix->about,
            'entries' => array_map($this->entry(...), $entries),
        ];

        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR)."\n";
    }

    /** @return array<string, mixed> the entry's fields in fixed order, with sorted sub-lists. */
    private function entry(MatrixEntry $entry): array
    {
        $conditions = $entry->conditions;
        usort($conditions, static fn (MatrixCondition $a, MatrixCondition $b): int => strcmp($a->id, $b->id));

        $sources = $entry->sources;
        usort($sources, static fn (MatrixSource $a, MatrixSource $b): int => strcmp($a->url, $b->url));

        return [
            'id' => $entry->id,
            'operation' => $entry->operation,
            'algorithm' => $entry->algorithm->value,
            'rebuilds_table' => $entry->rebuildsTable,
            'permits_concurrent_dml' => $entry->permitsConcurrentDml,
            'lock' => $entry->lock->value,
            'min_version' => $entry->minVersion,
            'max_version' => $entry->maxVersion,
            'conditions' => array_map(
                static fn (MatrixCondition $condition): array => ['id' => $condition->id, 'text' => $condition->text],
                $conditions,
            ),
            'sources' => array_map(
                static fn (MatrixSource $source): array => [
                    'url' => $source->url,
                    'anchor' => $source->anchor,
                    'retrieved' => $source->retrieved,
                ],
                $sources,
            ),
            'notes' => $entry->notes,
            'stability' => $entry->stability,
        ];
    }
}
