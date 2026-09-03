<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * What the end-of-life data says about the version a server reported.
 *
 * Five answers, not two, and the three that are neither "fine" nor "bad" are the reason this is an
 * enum rather than a boolean. A server can be past support, still supported, of a cycle this data
 * has never heard of, running a version string nothing could parse, or judged against a file that
 * does not record patch levels — and each of those is a different sentence to a reader and a
 * different thing to do next.
 */
enum PatchVerdict: string
{
    /** The cycle's support window has closed. A real finding, and the one this rule exists for. */
    case Ended = 'ended';

    /**
     * The cycle is still supported, and this data cannot say whether the PATCH level is current.
     *
     * Not a pass. `latest_patch` is deliberately null in the bundled file — a patch number moves
     * every few weeks, so a bundled copy would be wrong within a month of any release, and a wrong
     * "latest" produces either invented findings or invented confidence. So the honest answer is
     * that the question was not answered, with the reason attached.
     */
    case PatchLevelUnknown = 'patch_level_unknown';

    /** The cycle is supported and behind the latest patch this data records. */
    case BehindLatestPatch = 'behind_latest_patch';

    /** The cycle is supported and at or above the latest patch this data records. */
    case Current = 'current';

    /**
     * This data has no entry for the server's cycle.
     *
     * A major newer than the file, or older than anything it bothered to record. Either way the
     * only honest answer is that nothing was compared — a brand-new release is not "unsupported",
     * and an ancient one is not "fine".
     */
    case CycleUnknown = 'cycle_unknown';

    /** The version string could not be read as a cycle at all. */
    case VersionUnparsable = 'version_unparsable';

    /** Whether this verdict is a finding about the server rather than a gap in the data. */
    public function isFinding(): bool
    {
        return $this === self::Ended || $this === self::BehindLatestPatch;
    }
}
