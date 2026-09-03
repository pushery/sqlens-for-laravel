<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Tools\Tool;

/**
 * The one contract every database driver fulfills — and the only coupling between
 * the core and a driver. Everything driver-specific (PostgreSQL vs MySQL quoting,
 * catalogs, rules, readers) lives behind it, so the split from one package into
 * core + per-driver packages stays a mechanical move. The
 * contract itself carries no DB specifics — no pg_catalog, no information_schema,
 * no SQL fragments.
 *
 * The key is intentionally an open string, not a closed pgsql|mysql enum: a
 * third-party driver registers its own key through DriverRegistry::extend(). Which
 * keys are reserved lives in the registry, not here — a blocklist in two places is
 * exactly the divergence someone later misses.
 */
interface Driver
{
    /** The connection driver key — `pgsql`, `mysql`, or a registered third-party key. */
    public function key(): string;

    public function displayName(): string;

    /** The lowest server version this driver supports (a floor, not a target) — e.g. `18`, `8.4`. */
    public function minimumServerVersion(): string;

    public function documentationUrl(): string;

    /**
     * The rules this driver contributes. Empty for now — a deliberately documented
     * intermediate state, filled later by the PostgreSQL and MySQL rule packs.
     * The manager must never read an empty seam as "checked, all clean".
     *
     * @return iterable<Rule>
     */
    public function rules(): iterable;

    /**
     * The live-catalog readers this driver contributes. Empty for now, filled
     * later — the same documented intermediate state as rules(), never a silent
     * pass.
     *
     * @return iterable<object>
     */
    public function readers(): iterable;

    /**
     * The external tools this driver can lean on — the third thing a driver brings, beside its
     * rules and its readers.
     *
     * ## Why the DRIVER declares them rather than the service provider listing them
     *
     * Both shipped adapters are PostgreSQL-only, and each says so itself: `SquawkTool` and
     * `PglsTool` answer `$driver === 'pgsql'` from `supportsDriver()`. The provider nevertheless
     * assembled them as two concrete class names, which made the composition root the only place
     * that knew a PostgreSQL tool existed.
     *
     * That is fine in one package and impossible in two. This package promises that splitting it
     * into a core plus two driver packages would stay a mechanical move, and under that split these
     * classes ship with the PostgreSQL package — so a core provider naming them would reference
     * classes it cannot autoload. Declaring them here is what lets a driver package register its own adapters, which
     * is the whole point of the extension seam.
     *
     * Empty is a real answer: MySQL has no adapter at all, and a driver that returns nothing here is
     * saying so rather than leaving a gap. {@see Tool::supportsDriver()} stays
     * the runtime guard — this list is about which package OWNS a tool, not about which run may use
     * it.
     *
     * @return iterable<Tool>
     */
    public function tools(): iterable;
}
