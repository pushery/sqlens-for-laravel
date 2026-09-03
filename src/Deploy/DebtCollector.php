<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use DateTimeImmutable;
use DateTimeZone;
use Pushery\SQLens\Deploy\Contracts\ResolvesDebtStanding;

/**
 * The live view of a committed debt account: what is still owed, what was settled, and what nobody
 * could find out.
 *
 * ## What it adds over {@see DebtReconciliation}
 *
 * That one compares a ledger against what a RUN FOUND, which is the right question in a repository:
 * a debt the pending migrations no longer leave is settled. This one compares a ledger against the
 * CATALOG, object by object, and the difference is the third answer. "Not reported" and "not there"
 * look identical from the reconciliation's distance, and they are opposite situations — one is a
 * project that finished the job, the other is a table that was dropped, a schema outside this run's
 * scope, or a role that cannot see it.
 *
 * ## Why an absent account is not an empty one HERE
 *
 * On the recording side, a missing file means nothing has been recorded yet, and an empty account
 * is the honest reading. On the collecting side the file is the EXPECTED ARTEFACT: it not being
 * deployed, or `deploy.debt.path` resolving against the wrong working directory, is the likely
 * case — and "no open debts" would be the most comfortable possible wrong answer at exactly the
 * moment nobody can say. {@see DebtLedger::wasPresent()} carries that distinction out, and this is
 * where it is finally acted on.
 *
 * ## What it never does
 *
 * It does not write. Not to the database, and not to the ledger — a resolved debt is REPORTED as
 * resolved, and the entry is removed by a repository run that a person invoked, on a machine that
 * has a working copy. A deploy server has no business editing a file it merely has a copy of.
 */
final readonly class DebtCollector
{
    /**
     * @param  list<CollectedDebt>  $debts  one per ledger entry, in the ledger's own order
     * @param  bool  $ledgerMissing  the account was expected and is not there — reported, never read as "none"
     */
    private function __construct(
        public array $debts,
        public bool $ledgerMissing,
    ) {}

    /**
     * Ask the catalog where every recorded debt stands.
     *
     * @param  string  $asOf  the UTC calendar date the ages are measured against, passed in for the
     *                        same reason {@see DebtRegistrar} takes one: a collector that read the
     *                        wall clock would make two runs over one unchanged database disagree
     */
    public static function collect(DebtLedger $ledger, ResolvesDebtStanding $resolver, string $asOf): self
    {
        // An account this build cannot act on is somebody else's refusal, already named. Reporting
        // "nothing is owed" over it would be the second silent green in one code path.
        if (! $ledger->isUsable()) {
            return new self([], false);
        }

        if (! $ledger->wasPresent()) {
            return new self([], true);
        }

        $debts = [];

        foreach ($ledger->entries as $entry) {
            $debts[] = new CollectedDebt(
                $entry,
                $resolver->standingFor($entry),
                DebtAge::between($entry->firstSeen, new DateTimeImmutable($asOf, new DateTimeZone('UTC'))),
            );
        }

        return new self($debts, false);
    }

    /**
     * The debts the catalog still shows.
     *
     * @return list<CollectedDebt>
     */
    public function stillOpen(): array
    {
        return $this->withStanding(DebtStanding::StillOpen);
    }

    /**
     * The debts somebody finished.
     *
     * @return list<CollectedDebt>
     */
    public function resolved(): array
    {
        return $this->withStanding(DebtStanding::Resolved);
    }

    /**
     * The debts whose object could not be found — a question left open, not an answer.
     *
     * @return list<CollectedDebt>
     */
    public function unresolvable(): array
    {
        return $this->withStanding(DebtStanding::ObjectNotFound);
    }

    /** @return list<CollectedDebt> */
    private function withStanding(DebtStanding $standing): array
    {
        return array_values(array_filter(
            $this->debts,
            static fn (CollectedDebt $debt): bool => $debt->standing === $standing,
        ));
    }
}
