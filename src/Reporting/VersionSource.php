<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

/**
 * Where a version in the run context came from. The distinction is load-bearing:
 * environment skew (dev 18.2 / prod 18.0 / ci 18.4) is only visible when the run
 * context can tell a REAL detected version from an `assume_server_version` pin, so
 * a later rule can flag "you audited against a version you never ran on".
 */
enum VersionSource: string
{
    /** Read from the live server. */
    case Detected = 'detected';

    /** Taken from the `assume_server_version` pin, not from a real server. */
    case Assumed = 'assumed';
}
