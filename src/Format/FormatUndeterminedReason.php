<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * Why a formatter could not answer — a named value, never a free-text sentence.
 *
 * The three-valued discipline the rest of this package runs on, applied to formatting. A formatter
 * that returned the INPUT when it could not format would be indistinguishable from one that decided
 * the input was already correct, and `--check` would then report a file as clean because nothing
 * managed to look at it.
 *
 * Named rather than a string for the reason every other reason enum here is: a consumer has to be
 * able to COUNT them. "The binary is missing" happens on every machine that never installed it, and
 * "this statement could not be parsed" is a defect worth a ticket — a report where both arrive as
 * prose cannot tell a team which of the two they have.
 */
enum FormatUndeterminedReason: string
{
    /** The external binary this backend needs is not installed. */
    case ToolMissing = 'format_tool_missing';

    /*
     * ⚠️ THERE WAS A `ToolVersionUnsupported` CASE HERE, AND NOTHING COULD EVER PRODUCE IT.
     *
     * It read "it is installed, and its version is outside the window this adapter was measured
     * against" — a window that does not exist. The two OTHER external-tool adapters in this package
     * do have one (`SquawkTool::MINIMUM_VERSION`, `PglsTool::MINIMUM_VERSION`, each pinned in
     * lockstep with the version its lane installs); the format backends have no version concept at
     * all. Measured over the whole tree, the case was constructed 0 times in `src/`, referenced 0
     * times in `tests/`, and named in no documentation. Its own declaration was the only line that
     * mentioned it.
     *
     * That matters here more than it would in an internal enum: this is a STRING-BACKED enum whose
     * values travel in the JSON envelope, so the case list is part of what a consumer may switch on
     * — and 1.0 freezes it. A value that cannot occur is a promise with no producer, and removing it
     * after the first release would be a breaking change. Before it, it costs nothing.
     *
     * It comes back the day a format backend gets a measured version window, and not before. The
     * honest alternative — inventing a window nobody measured — would refuse working installs.
     */

    /** It ran and did not finish inside the budget. */
    case ToolTimedOut = 'format_tool_timed_out';

    /** It ran, failed, and said why in a way this adapter passes through rather than interprets. */
    case ToolRefused = 'format_tool_refused';

    /** The statement could not be parsed, so no formatting of it would be trustworthy. */
    case Unparsable = 'format_unparsable';

    /**
     * A style option this backend cannot express.
     *
     * Reported rather than silently ignored, and that is the whole point of having it: a formatter
     * that quietly dropped `leading_commas` would produce output a project did not ask for and no
     * signal that it had happened — and the next run would rewrite every file again.
     */
    case StyleNotExpressible = 'format_style_not_expressible';

    /** The backend does not handle this dialect at all. */
    case DialectUnsupported = 'format_dialect_unsupported';

    /**
     * The file itself could not be read — permissions, a broken symlink, a race with something
     * that deleted it mid-run.
     *
     * ⚠️ Its OWN case rather than folding into {@see self::Unparsable}, because that is what the
     * suite used to do and the answer it produced was actively misleading. An unreadable file was
     * read as an empty string, and an empty string is "the statement is empty, so there is nothing
     * to format" — a verdict about SQL, over a file whose SQL nobody ever saw. The run was right
     * that something was undetermined and wrong about what, so a reader went looking at their
     * query when the problem was a mode bit.
     *
     * A skip without a reason is a bug in this package. A skip with the WRONG reason is worse: it
     * spends someone's afternoon before it is caught.
     */
    case FileUnreadable = 'format_file_unreadable';
}
