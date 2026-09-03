<?php

declare(strict_types=1);

namespace Pushery\SQLens\Api;

/**
 * What a change to the promised surface costs.
 *
 * ## Three classes, and the middle one is why there are three
 *
 * A gate with two classes — breaking and not — has one predictable outcome: it blocks something a
 * maintainer knows is permitted, and gets switched off. The most likely candidate is a **severity
 * raise**, which the security promise explicitly allows within a minor. A gate that refused it
 * would be removed within a month, and after that nothing at all is protected.
 *
 * So the middle class exists to keep the outer two credible. It is not leniency; it is what makes
 * the strict class survivable.
 */
enum SurfaceChangeClass: string
{
    /**
     * A change that may only ship in a major release.
     *
     * These are the ones that break a consumer without warning: an id they suppressed disappears, a
     * prefix they grep for changes, an exit code their pipeline branches on means something else.
     */
    case ForbiddenWithoutMajor = 'forbidden_without_major';

    /**
     * A change that may ship in a minor, and is expected to.
     *
     * The package gets stricter over time — that is the product. What this class asks for is that
     * the change be VISIBLE, not that it be prevented.
     */
    case AllowedInMinor = 'allowed_in_minor';

    /** A change that costs nothing: a corrected documentation url, an added field. */
    case AlwaysAllowed = 'always_allowed';

    /** Whether a release that is not a major must refuse this change. */
    public function blocksMinorRelease(): bool
    {
        return $this === self::ForbiddenWithoutMajor;
    }
}
