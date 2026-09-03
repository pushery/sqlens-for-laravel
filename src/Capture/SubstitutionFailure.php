<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The substitutor could not produce one complete statement.
 *
 * It exists so "I could not render this" can never come back as a string that
 * merely looks finished. A guessed rendering would be read by every downstream
 * rule as the statement the database will actually see — and it would be wrong
 * in a way nothing further down could detect.
 */
final readonly class SubstitutionFailure
{
    public function __construct(
        public UndeterminedReason $reason,
        public string $detail,
    ) {}

    /** A binding whose type has no faithful literal form. */
    public static function unrepresentable(string $type, int $position): self
    {
        return new self(
            UndeterminedReason::PretendLimit,
            sprintf('Binding %d is a %s, which has no faithful SQL literal form.', $position, $type),
        );
    }

    /** The statement's placeholders and the bindings do not line up. */
    public static function countMismatch(int $placeholders, int $bindings): self
    {
        return new self(
            UndeterminedReason::PretendLimit,
            sprintf(
                'The statement has %d placeholder(s) but %d binding(s); refusing to guess which belongs where.',
                $placeholders,
                $bindings,
            ),
        );
    }
}
