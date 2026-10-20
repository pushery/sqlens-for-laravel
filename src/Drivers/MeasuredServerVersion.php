<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Pushery\SQLens\Contracts\DeclaresMeasuredServerVersion;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Rules\ServerVersion as ParsedVersion;

/**
 * Decides whether the server a run reasons about is newer than anything its driver's rules were
 * measured against, and marks the version a run header shows when it is.
 *
 * The other end of {@see ServerVersionFloor}. Below the floor the rules may be wrong in both
 * directions, and the run says so with a notice. Above the newest measured version they are applied
 * as written: the run continues, every verdict stands, and the header states the premise those
 * verdicts rest on, that the server behaves as the measured release did. A behavior the newer
 * release changed is not known to the rules, and a clean report says nothing about it.
 *
 * ## A mark in the header, and no notice among the findings
 *
 * A notice is a finding: a baseline can hide it, and a strict run counts it as undetermined. A newer
 * server is neither a defect nor a gap in the reading, and a pipeline that gates on undetermined
 * findings would stop on every server upgrade. The header is where a reader looks for what a run
 * assumed, and the mark rides in the version string itself, as the floor's does on the lint side,
 * so every reporter shows it without knowing about it.
 */
final readonly class MeasuredServerVersion
{
    /** The mark: the version shown, then the measured one twice, as `sprintf()` arguments. */
    private const string MARK = '%s — newer than %s, the newest version this release was measured against, '
        .'so the verdicts here describe how %s behaves';

    /**
     * The newest version the driver was measured against, when the version lies above it; null when
     * it does not, or when either side is unknown.
     */
    public function newerThanMeasured(?Driver $driver, ?ParsedVersion $version): ?string
    {
        if (! $driver instanceof DeclaresMeasuredServerVersion || ! $version instanceof ParsedVersion) {
            return null;
        }

        $measured = $driver->newestMeasuredServerVersion();
        $declared = ParsedVersion::parsePin($measured, $driver->key());

        // The declaration is package data. One this unit cannot read is a packaging bug, and a mark
        // on every header over it would turn that bug into advice about the user's server.
        if (! $declared instanceof ParsedVersion) {
            return null;
        }

        // The first release past the measured series: 19.0.0 after `18`, 8.5.0 after `8.4`. An if
        // rather than a three-line ternary, whose else line the coverage driver never marks as run.
        $next = ParsedVersion::of($declared->major + 1, 0, 0, $driver->key());

        if (str_contains($measured, '.')) {
            $next = ParsedVersion::of($declared->major, $declared->minor + 1, 0, $driver->key());
        }

        return $version->atLeast($next) ? $measured : null;
    }

    /** The version as the header shows it, marked when it lies above the measured one. */
    public function headerVersion(?Driver $driver, ?ParsedVersion $version, string $shown): string
    {
        $measured = $this->newerThanMeasured($driver, $version);

        return $measured === null ? $shown : sprintf(self::MARK, $shown, $measured, $measured);
    }

    /**
     * A server's own banner as the header shows it, marked when it lies above the measured version.
     *
     * A banner that names another engine is shown as it came. Whether that engine is supported at
     * all is the engine check's question, and a mark would answer a different one about a server
     * the driver does not describe.
     */
    public function headerBanner(?Driver $driver, string $banner): string
    {
        if (! $driver instanceof Driver || ServerVersionFloor::namesAnotherEngine($banner)) {
            return $banner;
        }

        $version = ParsedVersion::parse($banner, $driver->key());

        return $this->headerVersion($driver, $version instanceof ParsedVersion ? $version : null, $banner);
    }
}
