<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Findings\Finding;

/**
 * A finding that was hidden, together with the statement that hid it. The finding
 * is kept whole: suppression removes something from the GATE, never from the
 * record.
 */
final readonly class SuppressedFinding
{
    public function __construct(
        public Finding $finding,
        public Suppression $suppression,
    ) {}

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [...$this->finding->toArray(), 'suppression' => $this->suppression->toArray()];
    }
}
