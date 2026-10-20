<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * A driver that names the newest server version its rules were measured against.
 *
 * The floor says where the rules start to mean anything; this says where the evidence behind them
 * ends. A server between the two is what the rules were written for. A server above the newest
 * measured version still gets every verdict, and the run header marks its version so that a reader
 * knows those verdicts describe the older release: a behavior that changed in the newer one is not
 * known to the rules.
 *
 * ## Why this is a separate interface and not a method on `Driver`
 *
 * For the reason {@see AcceptsRunClock} gives: a method added to `Driver` breaks every
 * implementer, and `DriverRegistry::extend()` exists so that third-party implementers are a thing
 * this package has. A driver that does not implement this declares no measured version, and its
 * header is never marked.
 */
interface DeclaresMeasuredServerVersion
{
    /**
     * The newest server version the rules were measured against, written as `major` or
     * `major.minor` — e.g. `18`, `8.4`.
     *
     * The precision is part of the answer. `18` covers every 18.x release and `8.4` every 8.4.x
     * patch, so only a version past that series is newer than what was measured.
     */
    public function newestMeasuredServerVersion(): string;
}
