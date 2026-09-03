<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The pre-scan could not read a migration file.
 *
 * This exists so "could not parse" can never be returned as an empty hit list.
 * An empty list means "I looked and found nothing"; this means "I could not
 * look" — and a file whose syntax the scanner cannot follow is exactly a file
 * whose side effects it also cannot see. Collapsing the two would turn the most
 * suspicious input into the greenest result.
 */
final readonly class ScanFailure
{
    public function __construct(
        public string $file,
        public UndeterminedReason $reason,
        public string $detail,
    ) {}

    public static function unparsable(string $file, string $detail): self
    {
        return new self($file, UndeterminedReason::UnparsableMigration, $detail);
    }

    /**
     * @return array{file: string, reason: string, detail: string}
     */
    public function toArray(): array
    {
        return [
            'file' => $this->file,
            'reason' => $this->reason->value,
            'detail' => $this->detail,
        ];
    }
}
