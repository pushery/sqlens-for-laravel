<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Whether a column is encrypted at rest — as a three-valued answer, never a boolean.
 *
 * ## Why a boolean would be the wrong shape
 *
 * The rule this feeds reports a column only when it is NOT protected, so a wrong `false` is a
 * `critical`-shaped accusation against a column that is fine. Every way of not knowing — no model,
 * a model that will not construct, a custom cast nobody may execute, two models that disagree —
 * would have to collapse into one of the two answers, and both collapses are indefensible:
 * "unprotected" invents findings, "protected" hides them.
 *
 * So the third value is not a courtesy. It is the only honest answer for the cases that actually
 * dominate a real application, and it carries the reason so a reader knows what to go and look at.
 */
final readonly class ColumnProtection
{
    private function __construct(
        public bool $determined,
        public bool $protected,
        public ?UndeterminedReason $reason,
        /** The cast that decided it, or the detail that made the answer impossible. */
        public string $detail,
    ) {}

    /** The column carries one of Laravel's encrypted casts. */
    public static function protected(string $cast): self
    {
        return new self(true, true, null, $cast);
    }

    /** A model was read, and this column carries no encrypted cast. The only reportable answer. */
    public static function unprotected(): self
    {
        return new self(true, false, null, '');
    }

    /** The question could not be answered, and the reason says which of the ways it failed. */
    public static function undetermined(UndeterminedReason $reason, string $detail = ''): self
    {
        return new self(false, false, $reason, $detail);
    }

    /**
     * Whether this answer may produce a finding.
     *
     * Exactly one of the three states may, and naming it here keeps a rule from re-deriving the
     * rule — `! $protection->protected` would report every undetermined column as a violation,
     * which is the collapse this class exists to prevent.
     */
    public function isReportable(): bool
    {
        return $this->determined && ! $this->protected;
    }
}
