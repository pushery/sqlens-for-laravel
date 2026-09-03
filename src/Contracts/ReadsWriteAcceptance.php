<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Catalog\ReaderSession;
use Pushery\SQLens\Deploy\WriteAcceptance;
use Throwable;

/**
 * Answers whether the instance a deploy is pointed at will accept writes at all.
 *
 * ## Why this is a driver capability and not a `match` in the check
 *
 * `ReadOnlyTargetCheck` used to branch on `$context->driver === 'mysql'` and call one of two
 * private methods. That is a driver decision taken inside the core, which is the one thing the
 * driver boundary exists to prevent — and it was recorded as a named cost in the core-purity
 * register rather than excused. This seam is the remedy: the check asks a question,
 * each driver answers it in its own vocabulary, and the core learns no engine names.
 *
 * ## Why it is not {@see ReplicaProbe}
 *
 * That probe answers the same shape of question — "may I write here" — with a `bool`, and the
 * shadow captor needs nothing more. A deploy gate does: see {@see WriteAcceptance} for why a
 * standby and a read-only primary must not collapse into one answer. The two seams therefore stay
 * separate rather than one being widened to serve both, which would have made every shadow
 * provisioning carry a value object it never reads.
 *
 * ## It never writes
 *
 * The obvious way to answer "will writes be accepted" is to attempt one and roll it back. An
 * implementation must not: a rolled-back transaction still takes locks, still burns an
 * identifier, and still makes "this tool never writes to your database" false. Read what the
 * server publishes about itself, and nothing else.
 */
interface ReadsWriteAcceptance
{
    /**
     * Read the instance's write state over the session the run already opened.
     *
     * @throws Throwable when the server will not answer. The caller turns that into a named
     *                   `undetermined` — an unread setting is not a permissive one.
     */
    public function writeAcceptance(ReaderSession $session): WriteAcceptance;
}
