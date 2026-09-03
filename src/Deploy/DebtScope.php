<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * Which debts a run could have OBSERVED — and therefore which ones its silence is evidence about.
 *
 * ## The failure this exists to make impossible
 *
 * {@see DebtReconciliation} treats the ledger as authoritative about a debt's history and the run
 * as authoritative about its existence. That division is right, and it holds only while the run's
 * view covers the same population as the ledger. A run that looked at half of it and found nothing
 * in the other half is not reporting an absence — it is reporting that it did not look.
 *
 * The package already knew this and answered it once, locally: a `--file` lint run refuses to
 * record at all, because "recording from this view would remove entries for the honest reason that
 * this run could not see them". That refusal is correct and it does not generalize. `sqlens:lint`
 * reads migrations and never the catalog; `sqlens:audit` reads the catalog and never the
 * migrations. Neither can see the whole account, so under a refusal rule neither could ever record
 * — and the oldest debt a project carries, the one only the catalog knows about, would stay the
 * only one with no date.
 *
 * So the run says what it looked at, and reconciliation prunes only there. An entry outside the
 * scope is carried through untouched: not stale, not resolved, not reported as gone. It was simply
 * not this run's question.
 *
 * ## Why the scope is a PRODUCT of kinds and origins rather than a list of ids
 *
 * Kinds alone are not enough, and that is the whole reason this class has two fields. One
 * `NOT VALID` constraint recorded from a migration and one observed in the catalog are the same
 * KIND of debt; a lint run that scoped itself by kind would therefore claim authority over catalog
 * entries it structurally cannot see, and would delete every one of them on its next pass.
 *
 * Origins alone are not enough either: a run that produces one kind of debt has no opinion about
 * another kind found by the same origin, and pruning those would be the same mistake pointed the
 * other way.
 *
 * A list of ids would be a third thing and a worse one — it would make the scope depend on what the
 * run FOUND rather than on what it could have found, which collapses the distinction this class is
 * about. A run that finds nothing has to still be able to prove an absence within its scope.
 */
final readonly class DebtScope
{
    /**
     * @param  list<string>  $kinds  the debt kinds the run's claimants can produce
     * @param  list<DebtOrigin>  $origins  where the run's findings come from
     */
    private function __construct(public array $kinds, public array $origins) {}

    /**
     * The scope of a run, from the kinds it can produce and the origins it reads.
     *
     * @param  list<string>  $kinds
     * @param  list<DebtOrigin>  $origins
     */
    public static function of(array $kinds, array $origins): self
    {
        $unique = array_values(array_unique($kinds));
        sort($unique);

        return new self($unique, array_values(array_unique($origins, SORT_REGULAR)));
    }

    /**
     * A scope that covers everything.
     *
     * For a caller that genuinely sees the whole account, and for the tests of reconciliation
     * behavior that are not about scoping. Named rather than expressed as an empty scope, because
     * an empty list is what a caller passes by accident and "empty means everything" would turn a
     * mistake into a silent full-account prune — the exact failure the class exists to prevent.
     */
    public static function everything(): self
    {
        return new self([], []);
    }

    /** Whether this scope is the unrestricted one. */
    public function isUnrestricted(): bool
    {
        return $this->kinds === [] && $this->origins === [];
    }

    /** Whether this run looked at the population the entry belongs to. */
    public function covers(DebtEntry $entry): bool
    {
        if ($this->isUnrestricted()) {
            return true;
        }

        return in_array($entry->kind, $this->kinds, true)
            && in_array($entry->origin, $this->origins, true);
    }
}
