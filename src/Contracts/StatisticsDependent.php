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
 * turned on but no reader for this run — a lint run opens no catalog session — a
 * statistics-dependent rule is a named `statistics_unavailable` undetermined; with
 * statistics off, it does not run at all. A rule without this marker is unaffected
 * either way — it reads the migration and needs no live reading.
 *
 * It is a marker, not a method on the Rule contract, so a rule opts in by
 * implementing it and every existing rule stays untouched.
 *
 * The marker alone does not make `use_statistics` an honest switch: no rule in this package
 * implements it, so the lint filter it feeds is empty. What makes the key honest is
 * `PreflightService`, which withholds the statistics reader when it is off, so the deploy gate
 * does not escalate a severity by table size. This seam covers the lint half, for third-party
 * rules.
 */
interface StatisticsDependent {}
