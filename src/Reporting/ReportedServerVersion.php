<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

/**
 * One connection's server version as it appears in the reproducibility header:
 * the connection name, the version string exactly as reported (or pinned), and
 * whether it was detected from a live server or assumed from a pin. The version is
 * kept as the raw string — this is a reporting value, not a comparison value, so it
 * carries no driver-specific parsing (that lives in the rules layer).
 */
final readonly class ReportedServerVersion
{
    public function __construct(
        public string $connection,
        public string $version,
        public VersionSource $source,
    ) {}

    /**
     * Fixed-key-order array form for the JSON reporter.
     *
     * @return array{connection: string, version: string, source: string}
     */
    public function toArray(): array
    {
        return [
            'connection' => $this->connection,
            'version' => $this->version,
            'source' => $this->source->value,
        ];
    }
}
