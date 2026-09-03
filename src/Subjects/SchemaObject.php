<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Contracts\Subject;

/**
 * The subject for a live catalog object — the input of the audit, security and
 * deploy suites. Its type enum decides which rule classes can exist at all, so
 * it is cut in full here, not retrofitted.
 *
 * The edgecase flags (fromExtension, isPartition, schema scoping) exist from day
 * one because catalog dirt is rule reality, not an exception — otherwise they
 * get retrofitted through special paths later.
 *
 * The attribute bag stays typed on access (getString/getBool/…); a mixed array
 * would break Larastan max at the first rule.
 */
final readonly class SchemaObject implements Subject
{
    /**
     * @param  array<string, scalar|null>  $attributes
     */
    public function __construct(
        public SchemaObjectType $type,
        public string $qualifiedName,
        public ?string $parent,
        private array $attributes,
        private SubjectContext $context,
        public bool $fromExtension = false,
        public bool $isPartition = false,
    ) {}

    public function kind(): SubjectKind
    {
        return SubjectKind::SchemaObject;
    }

    public function identity(): string
    {
        return $this->type->value.':'.$this->qualifiedName;
    }

    public function context(): SubjectContext
    {
        return $this->context;
    }

    public function getString(string $key): ?string
    {
        $value = $this->attributes[$key] ?? null;

        return $value === null ? null : (string) $value;
    }

    public function getBool(string $key): ?bool
    {
        $value = $this->attributes[$key] ?? null;

        return $value === null ? null : (bool) $value;
    }

    public function getInt(string $key): ?int
    {
        $value = $this->attributes[$key] ?? null;

        return $value === null ? null : (int) $value;
    }

    /**
     * Every attribute this object carries, in a stable order.
     *
     * A bulk accessor beside the three typed ones, and it exists for exactly one caller: a drift
     * comparison has to serialize what an object IS, and asking key by key would mean the
     * serializer carrying a list of key names — a second place that has to learn about every new
     * attribute a reader starts attaching.
     *
     * Sorted here rather than trusted from the reader: a reader records attributes in whatever
     * order its query returned them, which is a property of the moment and not of the state. Two
     * readings of one schema must serialize identically or every comparison built on this is a
     * coin toss.
     *
     * @return array<string, scalar|null>
     */
    public function attributes(): array
    {
        $attributes = $this->attributes;

        ksort($attributes);

        return $attributes;
    }

    /**
     * The same object with more attributes merged over its own.
     *
     * The attribute bag stays private — a caller that could reach in would be a second place that
     * decides what an object's facts are. This is the one way to add to them, and it produces a NEW
     * object rather than mutating one, so a snapshot that has been handed out cannot change under
     * whoever is holding it.
     *
     * @param  array<string, scalar|null>  $attributes
     */
    public function withAttributes(array $attributes): self
    {
        return new self(
            $this->type,
            $this->qualifiedName,
            $this->parent,
            [...$this->attributes, ...$attributes],
            $this->context,
            $this->fromExtension,
            $this->isPartition,
        );
    }

    /**
     * Whether a rule may REASON about this object, as opposed to merely knowing it exists.
     *
     * True for everything nobody had to classify — a table has no comprehension question. For an
     * index it is the recorded verdict, and it is recorded on every index the readers produce, true
     * or false: a default of true over an unset attribute would answer "nobody looked" with "yes",
     * which is the silent green this package exists to refuse.
     */
    public function isFullyUnderstood(): bool
    {
        return $this->getBool('understood') ?? true;
    }

    public function hasAttribute(string $key): bool
    {
        return array_key_exists($key, $this->attributes);
    }
}
