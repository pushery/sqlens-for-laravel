<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

/**
 * Why the Squawk contribution is undetermined — the named reasons behind it.
 *
 * The backed values are stable ENGLISH identifiers that reach the JSON envelope, so they are
 * public API from 1.0 on. The text around them is translated; the identity is not.
 *
 * Several reasons and not one, because each is a different thing to go and do. The broader
 * rule-id namespace these sit in is settled separately; these follow its shape.
 *
 * Two of them are decided BEFORE the tool runs: an assumption SQLens cannot establish must not
 * be replaced by the tool's own default, because the tool's default is a different question than
 * the one the core rules answered.
 */
enum SquawkFailureReason: string
{
    /**
     * The tool did not run to a report: it timed out, could not start, exited with a code its
     * contract does not use, or wrote something that is not its JSON report at all.
     *
     * All four are "no measurement was taken", which is the distinction that matters against a
     * run that DID measure and found nothing. The specific cause travels in the detail.
     */
    case RunFailed = 'TOOL.SQUAWK.RUN_FAILED';

    /**
     * The tool ran, and said it could not parse the SQL it was given.
     *
     * Its own reason because it is a fact about OUR input, not about the tool: the capture form
     * and the tool's grammar disagreed. That is a bug report waiting to happen on this side, and
     * filing it under "the tool failed" would send it to the wrong place.
     */
    case Unparsable = 'TOOL.SQUAWK.UNPARSABLE';

    /**
     * The tool produced JSON, and an entry in it is not the shape this adapter reads.
     *
     * Separate from a failed run because the fix is different: this is a report in a shape
     * nobody here has measured — the thing the version window exists to prevent — and seeing it
     * means either the window is wrong or the tool changed inside it. Neither is fixed by
     * looking at why a process died.
     */
    case OutputUnreadable = 'TOOL.SQUAWK.OUTPUT_UNREADABLE';

    /**
     * SQLens could not establish which PostgreSQL version the run is about, or established one
     * the tool would refuse to read.
     *
     * The alternative — letting the tool fall back to its own default — is the failure this case
     * exists to prevent, and it is invisible. The target version is load-bearing: the same
     * `ADD COLUMN ... DEFAULT` is a finding at 10 and silence at 11 (measured). A run whose core
     * rules reasoned about one server and whose amplifier reasoned about another would produce
     * one report, with no sign that the two halves disagree.
     */
    case PgVersionUnknown = 'TOOL.SQUAWK.PG_VERSION_UNKNOWN';

    /**
     * Whether the statements run inside a transaction could not be established for this migration.
     *
     * Same shape, same reason: the tool has its own assumption, and adopting it silently would
     * mean judging a migration against a transaction model nobody chose. It also covers the case
     * where the statements of one migration DISAGREE — an explicit transaction opened partway
     * through — because a single invocation can only carry one assumption, and picking either is
     * picking one for the statements it does not fit.
     */
    case TransactionContextUnknown = 'TOOL.SQUAWK.TX_CONTEXT_UNKNOWN';

    /**
     * The single-file fast path ran, and the project has not allowed the tool into it.
     *
     * Reported rather than passed over, and the distinction from a disabled tool is the reason:
     * `enabled = false` says "never use this", which is a decision that needs no reminder.
     * `fast_path = false` says "use it, but not here" — the project DOES want these checks, so a
     * run that quietly left them out would be a smaller check wearing the same face as a full one.
     *
     * It exists because the fast path promises sub-second turnaround so a pre-commit hook stays
     * usable, and a shell-out to another program is exactly the cost that promise cannot absorb.
     */
    case SkippedOnFastPath = 'TOOL.SQUAWK.SKIPPED_FAST_PATH';
}
