<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One thing the migration role must be allowed to do, on one object.
 *
 * ## Why the underivable case lives here rather than being dropped
 *
 * A statement whose class this build cannot resolve — raw SQL with no recognizable target, a DDL
 * form nobody has taught the classifier — produces a requirement with a NULL class and a reason.
 * The alternative is to leave it out, and that is the failure this whole package is built against:
 * an object nobody could classify would then be indistinguishable from an object that needs no
 * privilege, and the check downstream would report a role as sufficient without having looked.
 */
final readonly class PrivilegeRequirement
{
    public function __construct(
        public string $object,
        public SchemaObjectType $objectType,
        /** Null when the statement's class could not be resolved — see the class note. */
        public ?PrivilegeClass $class,
        /** Why it could not be resolved; null when it could. */
        public ?string $undeterminedReason = null,
    ) {}

    public static function of(string $object, SchemaObjectType $type, PrivilegeClass $class): self
    {
        return new self($object, $type, $class);
    }

    /**
     * A requirement nobody could derive.
     *
     * The reason is mandatory and the constructor is the only way to build one without a class, so
     * an unclassifiable statement cannot become a silent absence.
     */
    public static function underivable(string $object, SchemaObjectType $type, string $reason): self
    {
        return new self($object, $type, null, $reason);
    }

    /**
     * Whether the class could be derived — and, for the analyzer, that reading it afterwards is safe.
     *
     * The assertion is the point rather than documentation. Without it every caller had to repeat an
     * `instanceof` the guard already made true, and each repetition carried an `else` that nothing
     * could enter: a branch which cannot be tested, cannot go red, and would silently swallow the
     * requirement a newly added class was created to express.
     *
     * @phpstan-assert-if-true !null $this->class
     */
    public function isDerived(): bool
    {
        return $this->class instanceof PrivilegeClass;
    }

    /** The stable sort key — same capture, same order, byte-identical reports. */
    public function sortKey(): string
    {
        // The underivable marker sorts LAST by design (`~` is above every letter in ASCII), so a
        // report's unanswered questions collect at the end rather than hiding between two answers.
        return $this->object.'|'.$this->objectType->value.'|'.($this->class instanceof PrivilegeClass ? $this->class->value : '~underivable');
    }

    /** @return array{object: string, object_type: string, privilege_class: string|null, undetermined_reason?: string} */
    public function toArray(): array
    {
        $projection = [
            'object' => $this->object,
            'object_type' => $this->objectType->value,
            'privilege_class' => $this->class?->value,
        ];

        return $this->undeterminedReason === null
            ? $projection
            : [...$projection, 'undetermined_reason' => $this->undeterminedReason];
    }
}
