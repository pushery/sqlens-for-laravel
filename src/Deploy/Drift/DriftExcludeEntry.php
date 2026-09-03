<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One difference a project has decided to live with.
 *
 * ## The reason is mandatory, and that is the whole design
 *
 * An entry that does not say why it exists is a grave rather than a tool. Six months on, nobody can
 * tell "we created this reporting view by hand and mean to keep it" from "somebody silenced a
 * finding on a Friday", and the only safe reading of an unexplained exclusion is to distrust all of
 * them. So a missing reason is a configuration error, not a default.
 *
 * ## Identity is the comparator's identity, not a second spelling of it
 *
 * The type plus the qualified name — exactly what {@see DriftEntry::sortKey()} uses. The file could
 * have carried `schema` and `name` as separate fields and read more like a form, and it would have
 * introduced a SECOND way to say which object is meant. Two spellings of one identity is how an
 * exclude comes to match nothing while looking perfectly correct.
 *
 * ## The attribute narrows a divergence, and only a divergence
 *
 * `null` excludes the object's disagreement whole. A name — `collation`, `default` — excludes only
 * that attribute, which is what a project usually means: the column is fine, its collation is
 * deliberately different. Excluding the object whole would also hide the day its TYPE changes.
 */
final readonly class DriftExcludeEntry
{
    public function __construct(
        public SchemaObjectType $type,
        public string $qualifiedName,
        public ?string $attribute,
        public string $reason,
    ) {}

    /**
     * Does this entry speak about that difference?
     *
     * An entry with no attribute matches the object; one with an attribute matches only when the
     * difference really names that attribute. A divergence on `default` is therefore untouched by an
     * exclusion written for `collation`, which is the point of allowing the narrowing at all.
     */
    public function covers(DriftEntry $entry): bool
    {
        if ($this->type !== $entry->type || $this->qualifiedName !== $entry->qualifiedName) {
            return false;
        }

        return $this->attribute === null || array_key_exists($this->attribute, $entry->changes);
    }

    /** The key two files sort by — identity first, then the attribute, so a diff stays readable. */
    public function sortKey(): string
    {
        return $this->type->value.':'.$this->qualifiedName.':'.($this->attribute ?? '');
    }

    /**
     * The sentence a stale entry is reported with.
     *
     * It names what was written down rather than what is missing, because the reader's next move is
     * to find that line in the file — and the reason is quoted so they can tell their own entry from
     * one a colleague added.
     */
    public function describe(): string
    {
        return $this->type->value.' `'.$this->qualifiedName.'`'
            .($this->attribute === null ? '' : ', attribute `'.$this->attribute.'`')
            .' (reason: '.$this->reason.')';
    }

    /**
     * The file's own shape, with a fixed key order.
     *
     * @return array{type: string, name: string, attribute: string|null, reason: string}
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type->value,
            'name' => $this->qualifiedName,
            'attribute' => $this->attribute,
            'reason' => $this->reason,
        ];
    }
}
