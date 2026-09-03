<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\OnlineDdl;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The outcome of asking {@see OperationKeyMapper} what operation a statement performs: either one
 * matrix operation key, or a named reason why none could be derived.
 *
 * Three-valued in the same shape as {@see MatrixResolution}, deliberately: a caller chains the two
 * and must treat "no key" and "no matrix entry for the key" the same way — as an undetermined that
 * carries its own reason, never as an absence to shrug off.
 */
final readonly class OperationKeyResolution
{
    private function __construct(
        public ?string $key,
        public ?UndeterminedReason $reason,
        public ?string $detail = null,
    ) {}

    public static function resolved(string $key): self
    {
        return new self($key, null);
    }

    public static function undetermined(UndeterminedReason $reason, string $detail): self
    {
        return new self(null, $reason, $detail);
    }

    public function isResolved(): bool
    {
        return $this->key !== null;
    }
}
