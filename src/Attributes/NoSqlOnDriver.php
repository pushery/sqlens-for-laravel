<?php

declare(strict_types=1);

namespace Pushery\SQLens\Attributes;

use Attribute;

/**
 * "This migration emits nothing on THAT driver, and here is why."
 *
 * ## The two states `CAP.L0.NOT_CAPTURABLE` could not tell apart
 *
 * That rule fires on "ran, succeeded, produced no SQL", and it is right to: a migration the run
 * checked nothing in should not read as clean. But two very different things land in it:
 *
 * - `up()` is empty because somebody forgot to fill it. A defect.
 * - `up()` is empty **on this driver** — `if ($driver === 'sqlite') { return; }`, or a file that
 *   only does anything on MySQL. A decision.
 *
 * A project with driver-conditional migrations therefore met a finding on every run about something
 * it had deliberately settled. That is the shape a rule gets silenced wholesale for, which costs
 * more than the finding was ever worth.
 *
 * ## Why not the baseline, which already accepts this id
 *
 * The baseline says "I know this finding", not "this migration is deliberately empty here", and the
 * gap shows the moment somebody touches the file:
 *
 * - a baseline line is bound to a LOCATION and does not survive a rename — the finding comes back
 *   and looks new;
 * - it lives somewhere else than the decision, so a reader of the migration cannot see that the
 *   emptiness is intended, and a reader of the baseline cannot see why;
 * - it keeps suppressing after the migration becomes empty BY ACCIDENT.
 *
 * The attribute has none of those properties: it sits on the decision, moves with the file, and
 * stops applying the moment its condition stops holding.
 *
 * ## The driver is named here AND checked against the run — both, and that is the design
 *
 * Naming it here alone would let a typo excuse everything silently. Taking it from the run alone
 * would let a bare attribute excuse any emptiness anywhere. Together, neither happens:
 *
 * | attribute says | run is on | `up()` empty ⇒ |
 * |---|---|---|
 * | `sqlite` | `sqlite` | no finding — the decision applies |
 * | `sqlite` | `pgsql`  | **finding**, exactly as before |
 * | `sqlyte` (a typo) | anything | **finding on every driver**, so the typo surfaces |
 *
 * A wrong driver name excuses NOTHING, which is what makes it visible rather than dangerous.
 *
 * ## Repeatable, because one migration can be empty on more than one driver
 *
 * And the reason is a required constructor argument, for the same reason {@see RawSql} makes it one:
 * an annotation without a reason is a PHP error before any analysis runs, which is the only
 * enforcement nobody can forget.
 *
 * ```php
 * #[NoSqlOnDriver('sqlite', reason: 'partial indexes are a PostgreSQL feature; SQLite gets the full index')]
 * public function up(): void
 * {
 *     if (DB::connection()->getDriverName() === 'sqlite') {
 *         return;
 *     }
 *     // …
 * }
 * ```
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
final readonly class NoSqlOnDriver
{
    /**
     * @param  string  $driver  the connection driver name this migration deliberately emits nothing
     *                          on — the same spelling Laravel reports, e.g. `sqlite`, `mysql`, `pgsql`
     * @param  string  $reason  why. An empty string is not one, and is treated as though the
     *                          attribute were absent — the finding stands.
     */
    public function __construct(
        public string $driver,
        public string $reason,
    ) {}
}
