<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * The result, with "no silent green" cast into the type: neither an undetermined
 * nor a not-applicable result is constructible without a named reason.
 *
 * There is no `skipped` and no `error`. A skip IS an undetermined, and it carries
 * its reason — that has not changed, and it is worth restating, because the fourth
 * value below is easy to mistake for one.
 *
 * `NotApplicable` is not a skip. A skip is a check that wanted to run and could
 * not; not-applicable is a check that had nothing to run against — MySQL has no
 * row-level security, a managed provider decides TLS above the server. The two
 * are separate because `--strict` escalates the first and must not escalate the
 * second, and because a report that showed them as one value would answer "was
 * this checked?" with the same word in both cases.
 *
 * There is deliberately no boolean projection (no isOk(), no passed(): bool):
 * collapsing three states onto two is exactly the silent-green failure this type
 * exists to prevent. Callers match on all three.
 */
final readonly class FindingStatus
{
    private function __construct(
        public Outcome $outcome,
        public ?UndeterminedReason $reason,
        /** Set exactly when the outcome is NotApplicable — the two reasons never share a field. */
        public ?NotApplicableReason $notApplicableReason = null,
    ) {}

    public static function pass(): self
    {
        return new self(Outcome::Pass, null);
    }

    public static function fail(): self
    {
        return new self(Outcome::Fail, null);
    }

    /**
     * The only way to reach the undetermined state — and it requires a reason.
     * There is no generic constructor that would let it be anonymous.
     */
    public static function undetermined(UndeterminedReason $reason): self
    {
        return new self(Outcome::Undetermined, $reason);
    }

    /**
     * The only way to reach the not-applicable state, and it requires a reason for
     * the same purpose `undetermined()` does: this is the state most likely to be
     * skimmed past, because it looks like nothing happened.
     */
    public static function notApplicable(NotApplicableReason $reason): self
    {
        return new self(Outcome::NotApplicable, null, $reason);
    }

    public function isPass(): bool
    {
        return $this->outcome === Outcome::Pass;
    }

    public function isFail(): bool
    {
        return $this->outcome === Outcome::Fail;
    }

    public function isUndetermined(): bool
    {
        return $this->outcome === Outcome::Undetermined;
    }

    public function isNotApplicable(): bool
    {
        return $this->outcome === Outcome::NotApplicable;
    }
}
