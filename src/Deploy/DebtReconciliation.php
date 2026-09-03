<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * What a run's debts and the committed ledger say about each other.
 *
 * Three questions, answered separately because they have three different answers and a caller needs
 * to tell them apart: what is owed and unrecorded, what is recorded and no longer owed, and what was
 * knowingly carried and has quietly stopped being detected.
 *
 * ## Why this is not {@see DebtLedger::merge()}
 *
 * That one is last-write-wins, and correctly so — it is how a hand-edited state gets applied. Using
 * it for the write path would be a disaster of exactly the quiet kind: every entry a run sees again
 * would be REPLACED by a freshly minted one, and with it would go `first_seen` (every age restarts
 * at zero), `state` (every acknowledgment silently reverts to open), `reason` (the argument
 * somebody wrote down disappears) and `review_at`. The ledger would still look healthy. It would
 * just have forgotten everything anybody ever decided about it.
 *
 * So here the LEDGER is authoritative about a debt's history and the RUN is authoritative about its
 * existence, and neither is allowed to answer the other's question.
 *
 * ## Why an acknowledged debt that vanishes is kept
 *
 * A debt with `state: acknowledged` carries a written reason for being tolerated. When a run stops
 * detecting it, dropping it silently would throw that reason away — and if the same debt reappears
 * later (a reverted migration, a rule that was briefly blind), it comes back as brand new, its age
 * restarted and its argument gone. It is therefore RETAINED and REPORTED, so somebody decides.
 *
 * An `open` entry that stops being detected is a different thing: nothing was decided about it, so
 * removing it is bookkeeping rather than a loss.
 */
final readonly class DebtReconciliation
{
    /**
     * @param  list<DebtEntry>  $unrecorded
     * @param  list<DebtEntry>  $stale
     * @param  list<DebtEntry>  $acknowledgedGone
     * @param  list<DebtEntry>  $recorded
     * @param  list<DebtEntry>  $outOfScope
     */
    private function __construct(
        /** Owed by this run and absent from the ledger. */
        public array $unrecorded,
        /** In the ledger as `open`, not owed any more — removable. */
        public array $stale,
        /** In the ledger as `acknowledged`, not detected any more — reported, never removed. */
        public array $acknowledgedGone,
        /** The entry set a recording run would write. */
        public array $recorded,
        /**
         * In the ledger and outside what this run looked at — kept, and NOT a finding.
         *
         * Exposed so a caller can say how much of the account it did not judge, which is the honest
         * counterpart to a settled report: "nothing to do" and "nothing to do in the part I read"
         * are different sentences.
         */
        public array $outOfScope,
    ) {}

    /**
     * Compare a ledger against the debts a run found, within the population the run could see.
     *
     * The scope is REQUIRED rather than defaulted to everything, and that is the safety property:
     * a caller that forgot to say what it looked at would otherwise claim authority over the whole
     * account and prune the half it never read. A caller that genuinely sees all of it passes
     * {@see DebtScope::everything()} and says so in one place a reader can find.
     *
     * @param  list<DebtEntry>  $candidates
     */
    public static function of(DebtLedger $ledger, array $candidates, DebtScope $scope): self
    {
        $existing = [];

        foreach ($ledger->entries as $entry) {
            $existing[$entry->id] = $entry;
        }

        $found = [];

        foreach ($candidates as $candidate) {
            $found[$candidate->id] = $candidate;
        }

        $unrecorded = [];

        foreach ($candidates as $candidate) {
            if (! isset($existing[$candidate->id])) {
                $unrecorded[] = $candidate;
            }
        }

        $stale = [];
        $acknowledgedGone = [];
        $outOfScope = [];
        // Keyed while it is built, so an entry cannot be added twice, and re-listed at the end —
        // the ledger sorts on write, but a caller comparing two reconciliations deserves a list
        // whose ORDER is not an artifact of hash iteration either.
        $recorded = [];

        foreach ($ledger->entries as $entry) {
            // Outside what this run looked at. Not stale — the run has no evidence either way, and
            // treating "did not look" as "not found any more" is how a partial view deletes the
            // other half of an account. Carried through untouched and not reported as gone, because
            // there is nothing to report: nobody asked this question.
            if (! $scope->covers($entry)) {
                $outOfScope[] = $entry;
                $recorded[$entry->id] = $entry;

                continue;
            }

            if (isset($found[$entry->id])) {
                // Still owed: the ledger's own entry survives untouched. Not the candidate — the
                // candidate carries this run's `first_seen` and a default state, and letting it win
                // is precisely the forgetting described above.
                $recorded[$entry->id] = $entry;

                continue;
            }

            if ($entry->state === DebtState::Acknowledged) {
                $acknowledgedGone[] = $entry;
                $recorded[$entry->id] = $entry;

                continue;
            }

            $stale[] = $entry;
        }

        foreach ($unrecorded as $entry) {
            $recorded[$entry->id] = $entry;
        }

        return new self($unrecorded, $stale, $acknowledgedGone, array_values($recorded), $outOfScope);
    }

    /** Whether the ledger already says exactly what this run found — so a recording run writes nothing new. */
    public function isSettled(): bool
    {
        return $this->unrecorded === [] && $this->stale === [];
    }
}
