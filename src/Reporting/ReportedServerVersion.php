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
     * What a run that read a server reports about its version: the version the server gave, as the
     * caller shows it, and the pin beside it when the project set one.
     *
     * The pin is stated even when it agrees with the server. "The pin matches" and "there is no pin"
     * are different facts about a project, and only one of them was somebody's decision.
     *
     * @return list<self>
     */
    public static function detectedAndPinned(string $connection, ?string $detected, mixed $pinned): array
    {
        $versions = $detected === null ? [] : [new self($connection, $detected, VersionSource::Detected)];

        if (is_string($pinned) && $pinned !== '') {
            $versions[] = new self($connection, $pinned, VersionSource::Assumed);
        }

        return $versions;
    }

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
