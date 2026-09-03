<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The outcome of asking the matrix about one operation: either the single applicable
 * {@see MatrixEntry}, or a NAMED undetermined — never a silent default. It is the same
 * three-valued shape the rest of the package uses, carried across the matrix boundary so the
 * resolver's uncertainty reaches the finding intact.
 *
 * `undetermined` always names a {@see UndeterminedReason} and, where one sharpens the message,
 * a detail (the operation key, or the exact predicate that could not be decided).
 */
final readonly class MatrixResolution
{
    private function __construct(
        public ?MatrixEntry $entry,
        public ?UndeterminedReason $reason,
        public ?string $detail = null,
    ) {}

    public static function resolved(MatrixEntry $entry): self
    {
        return new self($entry, null);
    }

    public static function undetermined(UndeterminedReason $reason, ?string $detail = null): self
    {
        return new self(null, $reason, $detail);
    }

    public function isResolved(): bool
    {
        return $this->entry instanceof MatrixEntry;
    }
}
