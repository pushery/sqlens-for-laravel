<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

/**
 * The suite axis — one of the four independent axes the engine filters a run by
 * (suite ∩ level ∩ version window ∩ category). A rule declares which suites it
 * runs in, so the promise "implement once, use twice" (an "FK without index"
 * rule runs in lint AND audit) needs no inheritance tree, only metadata.
 *
 * `security` is deliberately both a category (Category::Security) and a suite:
 * `sqlens:security` runs across lint+audit+analyse. The two are set
 * independently — a rule can be Category::Safety and still belong to
 * Suite::Security, or vice versa.
 *
 * The backed values are public API from 1.0 (they appear in config filters and
 * command names), so renaming one is a breaking change.
 */
enum Suite: string
{
    case Lint = 'lint';
    case Audit = 'audit';
    case Analyse = 'analyse';
    case Format = 'format';
    case Guard = 'guard';
    case Deploy = 'deploy';
    case Agent = 'agent';
    case Security = 'security';
}
