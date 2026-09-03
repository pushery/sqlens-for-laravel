<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

/**
 * What a baseline entry that matched nothing in the run should cost.
 *
 * A baseline nobody prunes grows shut: entries accumulate for findings that were
 * fixed months ago, and the file stops describing what the project actually
 * accepts. So a stale entry is always REPORTED. The only question is whether it
 * also stops the build, and that is a project's call — reporting by default
 * (a fresh baseline on a moving codebase would otherwise fail constantly), and
 * failing where the baseline is meant to be kept tight.
 *
 * "Stops the build" means the MISCONFIGURATION exit code, not a gate breach, and the distinction is
 * the whole reason the answer is useful: a rotten baseline is a broken instruction file rather than
 * a database that got worse, and misconfiguration is the one code that beats everything else — so a
 * run that also found something still reports the file nobody pruned. Both suites read the key from
 * the same place through {@see breaks()}; a project that never sets it keeps `report` and never sees
 * a code it did not ask for.
 */
enum StaleBaselinePolicy: string
{
    /** Name the stale entries; the run's verdict is unaffected. */
    case Report = 'report';

    /** Name them and treat the baseline as misconfigured. */
    case Error = 'error';

    /**
     * The policy a project configured, defaulting to the lenient one.
     *
     * Lenient about the VALUE on purpose, and only because somebody louder has already looked:
     * `sqlens.baseline.stale` is an enum leaf in the config schema, so a run carrying anything but
     * `report` or `error` was refused before it opened a connection. What reaches this method is
     * therefore either a legal value or a run that is already over — and falling back to the
     * stricter policy here would fail a build for a key whose real complaint was reported elsewhere.
     */
    public static function fromConfig(mixed $configured): self
    {
        return self::tryFrom(is_string($configured) ? $configured : '') ?? self::Report;
    }

    public function fails(): bool
    {
        return $this === self::Error;
    }

    /**
     * Whether these stale entries end the run as a misconfiguration.
     *
     * The whole decision lives HERE rather than as `->fails() && $stale !== []` at each runner,
     * because both suites read the same key from the same file and two spellings of one rule is
     * how they start disagreeing about what a rotten baseline costs. It answers about baseline
     * entries alone: an ignore rule that matched nothing is a different instruction with a notice
     * of its own, and folding it in would make this key fail a build for something it never named.
     *
     * @param  list<BaselineEntry>  $stale  the recorded entries that matched nothing this run
     */
    public function breaks(array $stale): bool
    {
        return $stale !== [] && $this->fails();
    }
}
