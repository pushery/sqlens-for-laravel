<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\ReaderSession;
use Throwable;

/**
 * Reads back the session timeouts a run's own defense put in force.
 *
 * ## Why a driver capability, and why a SECOND one
 *
 * `SessionDefenseAppliedCheck` branched on `$driver === 'mysql'` and called one of two private
 * methods — a driver decision inside the core, carried in the core-purity register as a named cost
 * This is the remedy, and it is deliberately not folded into
 * {@see ReadsWriteAcceptance}: that answers a question about the SERVER, this one about the
 * SESSION this run opened. One capability answering both would make an implementation that could
 * only do one of them impossible to write.
 *
 * ## The shape of the answer
 *
 * A map of setting name to milliseconds, or null where the server did not answer with a timeout at
 * all. The names are the ones the engine itself uses, because they are shown to an operator in the
 * run header and a name they cannot look up is worse than none: PostgreSQL answers
 * `statement_timeout` and `lock_timeout`, MySQL `max_execution_time`, `innodb_lock_wait_timeout`
 * and `lock_wait_timeout`, one for each bound its session defense sets.
 *
 * The caller judges every value and reports the keys whose bound is missing or looser than the run
 * asked. It looks a name up only to learn which of the run's bounds holds it, and a name it does not
 * know is held to being bounded at all, which works whatever an engine calls its settings.
 *
 * **Zero is a value, not an absence.** Zero means no timeout on both engines — exactly the state
 * the check exists to catch — so an implementation reports it as `0` and never folds it into null.
 */
interface ReadsSessionDefenseState
{
    /**
     * The timeouts in force on this session, in milliseconds, keyed by the name the engine uses.
     *
     * @return array<string, int|null>
     *
     * @throws Throwable when the session will not answer. An unread bound is not a bound, and the
     *                   caller turns this into a named `undetermined`.
     */
    public function timeoutsInForce(ReaderSession $session): array;
}
