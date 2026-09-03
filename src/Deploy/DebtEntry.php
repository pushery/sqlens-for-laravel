<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * One migration debt, as it is written to the ledger file.
 *
 * ## Why the identity is derived and not supplied
 *
 * `id` is a hash of what the debt IS — its kind and the object it is about — so the same debt
 * discovered by two runs, on two machines, months apart, carries the same id. A supplied id would
 * let two runs record the same outstanding debt twice, and a ledger that double-counts is worse
 * than none: the number it reports is the one thing anybody looks at.
 *
 * ## Why the MIGRATION is not part of it, though it used to be
 *
 * The migration is provenance, not identity. One `NOT VALID` constraint is one debt whether this
 * run learned about it from the migration that added it or from the catalog it now sits in — and
 * with the migration folded into the hash, those two ways of learning produced two entries for one
 * constraint. Not a theoretical split: the catalog side has no migration by construction (that is
 * what a legacy constraint IS), so the two ids could never agree, the reported age was wrong for
 * both halves, and reconciliation could not converge because each side wanted to remove the other's
 * entry.
 *
 * That is the same defect one level down from the one the canonicalization already fixes — two
 * spellings of an object are not two debts — and it has the same answer: identity is what the debt
 * is, and everything about how we came to know it is a field.
 *
 * It deliberately does NOT include `first_seen`, `state` or `reason`. Those describe what has
 * happened to the debt since; folding them into the identity would make acknowledging a debt look
 * like paying one and taking on a new one.
 *
 * ## Why the fields are ordered
 *
 * `toArray()` writes a fixed key order rather than whatever order the object was built in. Two runs
 * over the same state must produce byte-identical files, and PHP array order is insertion order —
 * so "the same entry" written by two code paths would otherwise differ in the diff while being
 * identical in meaning.
 */
final readonly class DebtEntry
{
    private function __construct(
        /** The stable identity, derived from kind + object. */
        public string $id,
        /** What KIND of debt this is — the rule family that recorded it, e.g. `not_valid_constraint`. */
        public string $kind,
        /** The rule that found it, so a reader can look up what it means. */
        public string $ruleId,
        /** `pgsql` or `mysql` — the same debt kind can exist on both, and they are not one debt. */
        public string $driver,
        /** The database object the debt is about: a table, column, index or constraint. */
        public string $object,
        /** The migration that created it, as the reference a reader can open, or empty for a catalog debt. */
        public string $migration,
        /** How the debt became known, which is what says what `firstSeen` means. */
        public DebtOrigin $origin,
        /** The UTC calendar date it was first recorded, `YYYY-MM-DD`. */
        public string $firstSeen,
        public DebtState $state,
        /** Why it is in this state — mandatory for an acknowledged debt, and free text otherwise. */
        public string $reason = '',
        /** When somebody said they would look again, `YYYY-MM-DD`, or null when nobody did. */
        public ?string $reviewAt = null,
    ) {}

    public static function of(
        string $kind,
        string $ruleId,
        string $driver,
        string $object,
        string $migration,
        string $firstSeen,
        DebtState $state = DebtState::Open,
        string $reason = '',
        ?string $reviewAt = null,
        ?DebtOrigin $origin = null,
    ): self {
        return new self(
            id: self::identity($kind, $object),
            kind: $kind,
            ruleId: $ruleId,
            driver: $driver,
            object: $object,
            migration: $migration,
            // Inferred from the migration reference when the caller does not say, because that
            // inference is exactly right and always has been: an empty reference has meant "found
            // in the catalog rather than in a file" since the field existed. A caller that KNOWS —
            // a catalog check that also happens to name a migration — passes it explicitly.
            origin: $origin ?? DebtOrigin::impliedBy($migration),
            firstSeen: $firstSeen,
            state: $state,
            reason: $reason,
            reviewAt: $reviewAt,
        );
    }

    /**
     * The derived identity.
     *
     * Joined with a byte no identifier can contain, so `a` + `bc` and `ab` + `c` cannot collide into
     * one hash — a separator that could appear in the parts is not a separator.
     */
    public static function identity(string $kind, string $object): string
    {
        return hash('sha256', implode("\x1f", [$kind, $object]));
    }

    /**
     * The entry as the ledger writes it, in the ONE documented key order.
     *
     * `review_at` is present even when null rather than omitted: a reader diffing two ledgers should
     * see a value change, not a key appear, and an absent key and a null one are the same statement
     * written two ways.
     *
     * `origin` sits beside `migration` rather than at the end, because the two answer one question
     * together: the reference, and whether there is one at all.
     *
     * @return array<string, string|null>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'kind' => $this->kind,
            'rule_id' => $this->ruleId,
            'driver' => $this->driver,
            'object' => $this->object,
            'migration' => $this->migration,
            'origin' => $this->origin->value,
            'first_seen' => $this->firstSeen,
            'state' => $this->state->value,
            'reason' => $this->reason,
            'review_at' => $this->reviewAt,
        ];
    }
}
