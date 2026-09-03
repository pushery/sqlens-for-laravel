<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * A stable hash over the FULL canonical form — not just the canonical SQL text, but
 * the canonical-form version, the statement kind, and the (order-independent) set
 * of targets, plus the transaction mode. It is the identity a baseline entry stores
 * and the later drift comparator compares, so a change a rule can see — a different
 * kind or a different target under identical SQL — MUST change it, or the hash would
 * be blind to exactly the fields rules read.
 *
 * Deterministic by construction: sets are ordered explicitly (never left to PHP
 * array order), the hash is content-only, and nothing here depends on locale, the
 * mbstring locale, or the timezone — the same state yields the same fingerprint on
 * a dev Mac and in CI.
 *
 * Three-valued: an undetermined form (a CanonicalizationFailure) gets its own
 * fingerprint that FOLDS IN the named reason and is disjoint from every determined
 * statement's — never collapsed onto one catch-all hash.
 */
final readonly class Fingerprint
{
    /** Unit and record separators — bytes that never occur in canonical SQL, so fields cannot bleed together. */
    private const string UNIT = "\x1f";

    private const string RECORD = "\x1e";

    private function __construct(public string $value) {}

    public static function of(CanonicalStatement|CanonicalizationFailure $form): self
    {
        return new self(hash('sha256', self::payload($form)));
    }

    /** Rehydrate a stored fingerprint (a baseline entry) without recomputing it. */
    public static function fromValue(string $value): self
    {
        return new self($value);
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->value, $other->value);
    }

    private static function payload(CanonicalStatement|CanonicalizationFailure $form): string
    {
        if ($form instanceof CanonicalizationFailure) {
            // The leading tag keeps an undetermined payload disjoint from every
            // determined one; the reason and detail make two undetermineds distinct.
            return implode(self::UNIT, ['undetermined', $form->reason->value, $form->detail]);
        }

        return implode(self::UNIT, [
            'v'.$form->formVersion->version,
            $form->statementKind instanceof StatementKind ? $form->statementKind->value : 'unclassified',
            $form->canonicalSql,
            $form->transaction->mode->value,
            $form->transaction->reason ?? '',
            self::targetPayload($form->targets),
        ]);
    }

    /**
     * The target SET, rendered order-independently: each target as "type name", then
     * sorted with an explicit byte-order flag so a shuffled-but-equal set hashes the
     * same and a changed member hashes differently.
     *
     * @param  list<StatementTarget>|null  $targets
     */
    private static function targetPayload(?array $targets): string
    {
        $rendered = array_map(
            static fn (StatementTarget $target): string => $target->type->value.' '.$target->qualifiedName(),
            $targets ?? [],
        );

        sort($rendered, SORT_STRING);

        return implode(self::RECORD, $rendered);
    }
}
