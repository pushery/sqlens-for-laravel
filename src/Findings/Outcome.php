<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * The outcomes a check can reach. The backed values are public API from 1.0 on
 * (they appear in JSON/SARIF output).
 *
 * This is the raw vocabulary; FindingStatus wraps it to enforce that neither
 * Undetermined nor NotApplicable is ever anonymous — each carries its reason.
 *
 * Three of these describe a check that RAN against something. The fourth says
 * there was nothing to run against, and it is separate for one concrete reason:
 * `--strict` escalates Undetermined and must not escalate NotApplicable. Folded
 * together, that distinction would be a convention rather than a property, and
 * the exit code of a run would move for a reason nobody chose.
 */
enum Outcome: string
{
    case Pass = 'pass';
    case Fail = 'fail';
    case Undetermined = 'undetermined';

    /**
     * The check does not apply to this instance — a different statement from
     * "could not be answered", and never a quiet pass.
     *
     * Spelled out rather than abbreviated: this value is read by people in a
     * JSON report and matched by tools in a pipeline, and `na` is ambiguous in
     * both audiences.
     */
    case NotApplicable = 'not_applicable';
}
