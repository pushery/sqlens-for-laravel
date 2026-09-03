<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * Why the Postgres Language Server contribution is undetermined — the named reasons behind it.
 *
 * The backed values are stable ENGLISH identifiers that reach the JSON envelope, so they are
 * public API from 1.0 on. The text around them is translated; the identity is not.
 *
 * Several reasons and not one, because each is a different thing to go and do. "The tool could
 * not reach the database" sends somebody to their credentials; "the tool answered in a shape this
 * adapter has not measured" sends somebody to the version pin. A single reason would send both to
 * neither.
 */
enum PglsFailureReason: string
{
    /**
     * The tool did not run to a report: it timed out, could not start, or exited with a code its
     * contract does not use.
     *
     * All of those are "no measurement was taken", which is the distinction that matters against a
     * run that DID measure and found nothing. The specific cause travels in the detail.
     */
    case RunFailed = 'TOOL.PGLS.RUN_FAILED';

    /**
     * The tool ran and could not reach the database it was pointed at.
     *
     * Its own reason, and the one this adapter needs most. Measured against 0.25.7: an unreachable
     * host, a database that does not exist and a role that does not exist all end the same way —
     * exit 1 with PLAIN TEXT on the output, even though `--reporter=json` was asked for. So the
     * absence of JSON is not evidence of a broken tool here; it is the ordinary shape of this
     * particular failure, and reading it as anything else would report a configuration problem as
     * a defect in the tool.
     *
     * It is emphatically not "no findings". A run that never reached the database has checked
     * nothing, and the whole point of a three-valued result is that those two cannot be the same
     * answer.
     */
    case DatabaseUnreachable = 'TOOL.PGLS.DATABASE_UNREACHABLE';

    /**
     * The tool produced JSON, and it is not the shape this adapter reads.
     *
     * Separate from a failed run because the fix is different: this is a report nobody here has
     * measured — the thing the version window exists to prevent — and seeing it means either the
     * window is wrong or the tool changed inside it. Neither is fixed by looking at why a process
     * died.
     */
    case OutputUnreadable = 'TOOL.PGLS.OUTPUT_UNREADABLE';

    /**
     * SQLens could not assemble the connection details the tool needs.
     *
     * Decided BEFORE the tool runs, and deliberately so: the alternative is letting the tool fall
     * back to its own defaults, which are `localhost:5432/postgres`. A run whose core rules
     * reasoned about the audited database and whose amplifier reasoned about whatever answers on
     * the local machine would produce one report, with nothing in it saying the two halves are
     * about different servers.
     */
    case ConnectionIncomplete = 'TOOL.PGLS.CONNECTION_INCOMPLETE';
}
