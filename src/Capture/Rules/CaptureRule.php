<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Rules;

use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * A level-0 rule that judges a migration's CAPTURE OUTCOME rather than its SQL.
 *
 * The standard rule engine dispatches over three subject kinds (captured SQL, a
 * catalog object, a raw-SQL callsite), and that set is deliberately sealed. But
 * the lint suite's lowest assurances are not about SQL at all — they are about
 * whether the SQL could be captured in the first place: was anything capturable,
 * did the pretend run throw. A migration that produced no statement has no
 * MigrationSql subject to hand a rule, so these checks cannot be engine rules.
 *
 * They are their own small family instead, evaluating a CaptureResult directly.
 * Each still carries the full published rule metadata (a stable id, a level, a
 * category, a documentation page) so a report groups it, a baseline addresses it,
 * and the generated docs list it exactly like any rule — the difference is where
 * the input comes from, not what a user sees.
 *
 * Side-effect free with respect to the database, like every rule: it reads a
 * CaptureResult the capture layer already produced and touches no connection.
 */
interface CaptureRule
{
    /** The published metadata — the same surface a Subject-based rule carries. */
    public function metadata(): CaptureRuleMetadata;

    /**
     * Whether this rule judges the given capture outcome. A result it does not
     * apply to produces NO finding — "not applicable" is silence, never a pass.
     */
    public function appliesTo(CaptureResult $result): bool;

    /**
     * The finding for a result this rule applies to. The project root turns the
     * absolute migration path into the repo-relative location a report shows.
     */
    public function evaluate(CaptureResult $result, SubjectContext $context, string $projectRoot): Finding;
}
