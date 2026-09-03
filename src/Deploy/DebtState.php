<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * Where a migration debt stands with the people who owe it.
 *
 * The three values are the vocabulary the ledger's own lifecycle uses — a debt is discovered, it may
 * be deliberately carried, and it is eventually paid. They are typed rather than free strings for
 * the reason every recorded state is: a typo in a hand-edited ledger would otherwise read as a
 * fourth state, and a reader that does not recognize a state has to guess whether to count it.
 *
 * What is NOT here is the TRANSITION table — which change is allowed from which state, and what a
 * resolved debt reappearing means. That is a separate question with its own answer, and inventing it
 * alongside the file format would be a decision made in the wrong place.
 */
enum DebtState: string
{
    /** Recorded and outstanding: found, not paid, not deliberately accepted. */
    case Open = 'open';

    /**
     * Deliberately carried, with a reason.
     *
     * Different from `open` in exactly one way, and it is the way that matters: somebody looked at
     * this one and decided. A ledger that could not say so would push every accepted debt back into
     * the same list as the ones nobody has read yet, and the list would stop being read.
     */
    case Acknowledged = 'acknowledged';

    /** Paid: the state the debt described is gone from the database. */
    case Resolved = 'resolved';
}
