<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Statistics;

/**
 * How much of a storage picture the reading actually got.
 *
 * Three states rather than a boolean, because the middle one is the ordinary one. Through SQL
 * alone, at least one major engine will tell you how much space a database occupies and will not
 * tell you how much room is left on the volume underneath it — that is not a degraded server or a
 * misconfigured role, it is Tuesday. A two-valued answer would have to file the common case as
 * either a success or a failure, and both readings mislead: as a success it invites a consumer to
 * act on a number it does not have, and as a failure it buries the genuinely broken case in noise
 * nobody reads.
 *
 * The backed values reach the JSON output and are public API from 1.0.
 */
enum HeadroomReadability: string
{
    /** Both numbers arrived: how much is used, and how much is left. */
    case Complete = 'complete';

    /**
     * The size is known and the free space is not — the ordinary shape on at least one engine.
     *
     * A consumer may weight by how large the thing is; what it may not do is answer "will this fit".
     */
    case SizeOnly = 'size_only';

    /** Neither number arrived. Nothing about capacity may be concluded, in either direction. */
    case Unreadable = 'unreadable';

    /** Whether a capacity question — "is there room for this rewrite" — can be answered at all. */
    public function answersCapacity(): bool
    {
        return $this === self::Complete;
    }
}
