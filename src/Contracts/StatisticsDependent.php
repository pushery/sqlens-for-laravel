<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * A marker a rule adds when its verdict depends on the server's table statistics —
 * row counts, index selectivity, bloat — not on the migration text alone. Such a
 * rule cannot conclude from the SQL by itself; it needs a reading of the live
 * instance.
 *
 * The marker is what the run consults for the `use_statistics` axis: with statistics
 * turned on but no reader available (the reader lands with the audit suite), a
 * statistics-dependent rule is a named `statistics_unavailable` undetermined; with
 * statistics off, it does not run at all. A rule WITHOUT this marker is unaffected
 * either way — it reads the migration and needs no live reading.
 *
 * It is a marker, not a method on the Rule contract, so a rule opts IN by
 * implementing it and every existing rule stays untouched. The reader itself arrives
 * with the audit suite; until then this is the seam that keeps `use_statistics` an
 * honest three-valued switch rather than a config key with no effect.
 */
interface StatisticsDependent {}
