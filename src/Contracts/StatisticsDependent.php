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
 * turned on but no reader for THIS run — a lint run opens no catalog session — a
 * statistics-dependent rule is a named `statistics_unavailable` undetermined; with
 * statistics off, it does not run at all. A rule WITHOUT this marker is unaffected
 * either way — it reads the migration and needs no live reading.
 *
 * It is a marker, not a method on the Rule contract, so a rule opts IN by
 * implementing it and every existing rule stays untouched.
 *
 * ⚠️ AND THE SENTENCE THAT USED TO CLOSE THIS BLOCK WAS THE PROBLEM IT CLAIMED TO SOLVE. It said
 * the marker "keeps `use_statistics` an honest three-valued switch rather than a config key with
 * no effect" — while no shipped rule implemented the marker, so the filter it feeds was always
 * empty and the switch had exactly the effect it was supposed to be saved from. What makes the key
 * honest is `PreflightService`, which withholds the statistics READER when it is off, so the
 * deploy gate stops escalating a severity by table size. This seam covers the lint half, and it
 * covers it for third-party rules — no rule in this package reasons about statistics yet.
 */
interface StatisticsDependent {}
