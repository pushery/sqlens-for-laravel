<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * The ledger's account of one debt, carried on the finding that reports it.
 *
 * ## Why the finding needs this at all
 *
 * A debt IS a finding already — {@see DebtNotices} builds them with the same factories every rule
 * uses, and they travel in the same list. What they could not do until now is say what they are in a
 * form a machine can read: the kind, the age and the state reached a consumer only as English prose
 * inside `message`, so the only way to get the age off a finding was to parse the sentence
 * "open since 94 days". A report that has to be read as literature is not a report an agent, a
 * dashboard or a gate can act on.
 *
 * ## Why the word `kind` is copied and not invented
 *
 * `debt_kind` already exists in two other places in the same document — on a remediation payload
 * ("applying this fix would OPEN a debt of this kind") and in the rule catalog. This one answers a
 * third question: "this finding IS a debt of this kind". They are at different depths so nothing
 * collides, and they must never disagree, which is why the value here is the registrar's own word
 * off the entry rather than a second spelling produced here.
 *
 * ## Why an unknown age is an ABSENT key rather than a null
 *
 * The projection omits nulls, so `age_days` disappears when the age could not be computed. That
 * would be a silent absence — except `first_seen` is always present, because it is the raw string
 * the ledger holds whether or not it parses. So a consumer that finds `first_seen` and no `age_days`
 * is looking straight at the reason: that date could not be read. The pair is the named absence;
 * neither half on its own would be.
 */
final readonly class DebtContext
{
    /**
     * @param  string  $kind  the registrar's word for what is owed, copied off the entry
     * @param  string  $firstSeen  the raw ledger value, present even when it cannot be parsed
     * @param  int|null  $ageDays  whole days outstanding, or null when `firstSeen` would not read
     */
    private function __construct(
        public string $kind,
        public string $firstSeen,
        public ?int $ageDays,
        public DebtState $state,
    ) {}

    /**
     * The context for a debt whose age this run computed.
     *
     * Takes the {@see DebtAge} rather than an int, so "unknown" arrives as the value object that
     * already knows it is unknown. A caller passing `?int` would have to decide what a null meant,
     * and the two callers would eventually decide differently.
     */
    public static function of(DebtEntry $entry, DebtAge $age): self
    {
        return new self($entry->kind, $entry->firstSeen, $age->days(), $entry->state);
    }

    /**
     * The context for a debt this run has not aged — the repository side, which reconciles what a
     * run owes against the file and has no reference date in hand at that point.
     *
     * Separate from {@see self::of()} rather than a nullable argument: "we did not compute an age"
     * and "we computed one and it was unreadable" are different facts, and both end up with no
     * `age_days`. Keeping the two entry points apart is what stops a caller from reaching for the
     * wrong one without noticing.
     */
    public static function unaged(DebtEntry $entry): self
    {
        return new self($entry->kind, $entry->firstSeen, null, $entry->state);
    }

    /**
     * @return array{debt_kind: string, first_seen: string, age_days?: int, debt_state: string}
     */
    public function toArray(): array
    {
        return array_filter([
            'debt_kind' => $this->kind,
            'first_seen' => $this->firstSeen,
            'age_days' => $this->ageDays,
            'debt_state' => $this->state->value,
        ], static fn (mixed $value): bool => $value !== null);
    }
}
