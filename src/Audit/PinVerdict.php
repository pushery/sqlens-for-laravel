<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

/**
 * Whether the server a run actually reached is the one it was pinned to.
 *
 * ## Why this is four states and not a boolean
 *
 * Pinning a host decides which server an audit reads. Verifying the pin afterwards is a different
 * question, and the tempting shape — "does the observed host equal the pinned one?" — collapses two
 * situations that must not be collapsed: *the server said something else* and *the server said
 * something that cannot be compared*.
 *
 * The second one is the common case, not an edge. A project pins `db2.internal`; PostgreSQL answers
 * `inet_server_addr()` with `10.0.0.7`. Those may well be the same machine, and SQLens has no way to
 * know without resolving DNS — which would put a network lookup, and a second source of truth, in
 * the middle of a run that promises determinism. So it does not resolve; it reports.
 *
 * Folding that into "verified" would be the package's own silent green: a run that never checked,
 * reported as a run that checked and was happy. Folding it into "divergent" would be worse — a hard
 * refusal on every correctly configured project that pins by name, which is most of them.
 */
enum PinVerdict: string
{
    /** Nothing was pinned, so there is nothing to verify. Not a pass and not a gap. */
    case NotPinned = 'not_pinned';

    /** The server named the host that was pinned. The report can assert which database it read. */
    case Confirmed = 'confirmed';

    /**
     * The server named a DIFFERENT host than the one pinned.
     *
     * The run is reading a database nobody asked for — the exact failure pinning exists to prevent,
     * arrived at anyway. Refused rather than reported, because every finding that followed would be
     * about the wrong server while looking indistinguishable from a real report.
     */
    case Divergent = 'divergent';

    /**
     * The two cannot be compared: a name against an address, or a server that named nothing at all.
     *
     * Reported as `undetermined` with a named reason. The audit still runs — the pin did take
     * effect at the driver, and refusing here would make pinning by hostname impossible — but the
     * report says out loud that the identity was not confirmed.
     */
    case Unverifiable = 'unverifiable';
}
