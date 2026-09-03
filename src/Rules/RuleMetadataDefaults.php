<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Severity\Severity;

/**
 * The metadata answers every rule gives the same way — held once, so two rule families cannot drift.
 *
 * A rule has to answer a dozen questions about itself, and almost all of them have one sensible
 * answer that almost every rule keeps: no severity, deterministic, not deprecated, no version
 * window, no downtime class. Those answers were written into the lint base, which was fine while
 * there was one base — and the moment a second family needs them, copying them is how the two
 * families start disagreeing about what "the default" is.
 *
 * What is deliberately NOT here: `id()`, `level()`, `category()` and anything about EVALUATION. An
 * id and a level have no sensible default, a category is a claim each family makes for itself, and
 * how a rule reaches a verdict is the thing the families genuinely differ about — which is the whole
 * reason there is more than one of them.
 */
trait RuleMetadataDefaults
{
    /**
     * The stability a rule carries unless it says otherwise.
     *
     * Before 1.0 that is `stable`: the preview tier exists so a rule added to a published product
     * cannot break somebody's pipeline by starting to fire, and before the first release there is no
     * such pipeline. This flips to `preview` for rules added after 1.0 — HERE, once, so the change
     * is one line rather than a sweep.
     */
    public const StabilityTier DEFAULT_STABILITY = StabilityTier::Stable;

    /**
     * Null throughout: safety is gated by LEVEL, not by severity. Severity models risk for the
     * security and privacy categories, and merging the two axes is exactly what makes a reader
     * unable to explain why a level-2 run reported a critical.
     */
    public function severity(): ?Severity
    {
        return null;
    }

    public function stability(): StabilityTier
    {
        return self::DEFAULT_STABILITY;
    }

    public function confidence(): Confidence
    {
        return Confidence::Deterministic;
    }

    public function deprecation(): ?RuleDeprecation
    {
        return null;
    }

    /** Unbounded unless a rule narrows it — most rules hold on every version. */
    public function versionWindow(): VersionWindow
    {
        return new VersionWindow(null, null);
    }

    /**
     * Unset here rather than guessed: the deploy impact of an operation is a per-rule judgment, and
     * a family-wide default would be wrong for most of them.
     */
    public function downtimeClass(): ?DowntimeClass
    {
        return null;
    }

    /**
     * Derived from the id, never hand-written: `PG.L2.INDEX_NOT_CONCURRENT` becomes
     * `…/rules/pg-l2-index-not-concurrent`. Flat, one segment — the same slug the fixture directory
     * and the documentation file carry, so one id has one slug everywhere.
     */
    final public function documentationUrl(): string
    {
        return RuleDocumentationUrl::for($this->id());
    }
}
