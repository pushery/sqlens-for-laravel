<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\SkipReason;
use Pushery\SQLens\Exceptions\InvalidReadability;

/**
 * How completely one object was read, and — when the answer is "not completely" — WHY.
 *
 * The type is the guardrail, not a convention. The constructor is private and the only way to a
 * non-complete state requires a reason plus the names of the fields that are missing. So "something
 * was withheld and nobody said what" is not a state this model can represent, which is a stronger
 * promise than any review can make. It is the same discipline
 * {@see CatalogSkip} applies one level up.
 *
 * Why the field names and not just a reason: a role read without its password hash and a role read
 * without its memberships are both `partial` for `insufficient_privilege`, and a rule about hash
 * types must be able to tell which of the two it is holding. Otherwise every rule downstream has to
 * treat every partial object as unusable, and a suite that goes quiet on a managed database is a
 * suite nobody keeps.
 */
final readonly class Readability
{
    /**
     * @param  list<string>  $withheldFields  sorted, so two readings of the same state compare equal
     */
    private function __construct(
        public ReadabilityState $state,
        public ?SkipReason $reason,
        public array $withheldFields,
        public ?string $detail,
    ) {}

    /** Everything this object claims was read. */
    public static function complete(): self
    {
        return new self(ReadabilityState::Complete, null, [], null);
    }

    /**
     * Some fields were withheld — which ones, and why.
     *
     * @param  list<string>  $fields  at least one; a partial reading that names no missing field is
     *                                indistinguishable from a complete one
     *
     * @throws InvalidReadability
     */
    public static function partial(SkipReason $reason, array $fields, ?string $detail = null): self
    {
        if ($fields === []) {
            throw InvalidReadability::partialWithoutFields($reason);
        }

        sort($fields);

        return new self(ReadabilityState::Partial, $reason, $fields, $detail);
    }

    /** Nothing beyond the object's identity could be read. */
    public static function unreadable(SkipReason $reason, ?string $detail = null): self
    {
        return new self(ReadabilityState::Unreadable, $reason, [], $detail);
    }

    /** Whether this reading may be used to conclude anything about the named field. */
    public function covers(string $field): bool
    {
        return match ($this->state) {
            ReadabilityState::Complete => true,
            ReadabilityState::Unreadable => false,
            ReadabilityState::Partial => ! in_array($field, $this->withheldFields, true),
        };
    }

    /**
     * The deterministic projection, with a fixed key order.
     *
     * The reason is written even when null so the shape never varies with the contents — the same
     * convention every count map in this package follows, and for the same reason: a consumer
     * comparing two reports should be reading the values, not discovering which keys exist today.
     *
     * @return array{state: string, reason: string|null, withheld_fields: list<string>, detail: string|null}
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state->value,
            'reason' => $this->reason?->value,
            'withheld_fields' => $this->withheldFields,
            'detail' => $this->detail,
        ];
    }

    /** The stable key two readings compare on — used by the objects' own `equals()`. */
    public function sortKey(): string
    {
        return $this->state->value.'|'.($this->reason->value ?? '').'|'.implode(',', $this->withheldFields);
    }
}
