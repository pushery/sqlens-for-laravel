<?php

declare(strict_types=1);

namespace Pushery\SQLens\Severity;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Levels\Level;

/**
 * One finding, measured against both gates, with the blocking axis NAMED.
 *
 * ## Why the axis travels with the verdict
 *
 * "This run breached a gate" is not actionable. A level breach is fixed by fixing the migration or
 * by lowering the level on purpose; a severity breach is fixed by fixing the migration or by a
 * deliberate decision about risk — and the second is a conversation the first never needs. A report
 * that gave only a total would send every reader to work out which of the two they were looking at,
 * from a number that cannot say.
 *
 * ## Why a finding never blocks on both
 *
 * Each finding belongs to exactly ONE axis, decided by its category ({@see GateAxis::forCategory()}).
 * Security and privacy findings answer to severity and are not measured against the level at all;
 * everything else answers to the level and — even carrying a severity — cannot be blocked by the
 * risk gate. That is the invariant this object exists to make checkable: `blockedBy` is one value,
 * so a report cannot double-count, and a finding cannot be smuggled past one gate by the other.
 *
 * The exit code reads `blockedBy` rather than recomputing anything, and both axes produce the SAME
 * "findings over the gate" code: a pipeline needs to stop either way, and a second code would make
 * a critical security finding look like a misconfiguration.
 */
final readonly class GateDecision
{
    private function __construct(
        /**
         * Which gate this finding ANSWERS TO, blocking or not.
         *
         * Separate from `blockedBy` because the two questions have different answers for most
         * findings, and only one of them can be reconstructed afterwards. A security check that
         * came back `undetermined` blocks nothing — but it is still a fact about the risk axis, and
         * a reader who wants "how many security checks could not conclude" needs the axis to
         * survive the non-blocking verdict. Without this field the only way back to it is to ask
         * the category again, which is the second place the axis rule would then live.
         */
        public GateAxis $axis,
        /**
         * The check did not conclude — neither a pass nor a fail.
         *
         * Carried on the decision rather than left to the reader, so "did not block" cannot be
         * mistaken for "was fine". Those are the two states a three-valued model exists to keep
         * apart, and they are indistinguishable from `blockedBy === null` alone.
         */
        public bool $undetermined,
        /** True when the level gate is what stops this finding. */
        public bool $levelBlocking,
        /** True when the risk gate is what stops this finding. */
        public bool $severityBlocking,
        /** Which gate stopped it, or null when neither did. Never both. */
        public ?GateAxis $blockedBy,
    ) {}

    /**
     * Measure one finding against both gates.
     *
     * Only a FAILING finding can breach a gate. A pass has nothing to breach, and an undetermined
     * is a check that did not conclude — turning that into a gate breach here would quietly make
     * "we could not tell" mean "you failed", which is the `strict_undetermined` decision and belongs
     * to the project, not to this object.
     */
    public static function for(Finding $finding, Level $level, SeverityGate $severity): self
    {
        // The category decides the axis, once, and it decides it for EVERY finding — a pass and an
        // undetermined belong to an axis too, they just do not breach it. Deciding it here rather
        // than at each consumer is what keeps a severity on a safety rule from doing anything at all.
        $axis = GateAxis::forCategory($finding->category);

        if (! $finding->status->isFail()) {
            return new self($axis, $finding->status->isUndetermined(), false, false, null);
        }

        if ($axis === GateAxis::Severity) {
            $blocking = $severity->blocks($finding);

            return new self($axis, false, false, $blocking, $blocking ? GateAxis::Severity : null);
        }

        $blocking = $level->includes($finding->level);

        return new self($axis, false, $blocking, false, $blocking ? GateAxis::Level : null);
    }

    public function blocks(): bool
    {
        return $this->blockedBy instanceof GateAxis;
    }
}
