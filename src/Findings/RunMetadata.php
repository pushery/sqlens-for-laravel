<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Subjects\CaptureMode;

/**
 * The run parameters that make a result reproducible: which server version(s)
 * were addressed (a read/write split can audit several instances), which tool
 * versions ran, the capture mode, the profile, the strict-tools flag and how
 * much of the time budget was consumed.
 *
 * These belong to the aggregate, not the reporter — every reporter shows them so
 * a reader can tell exactly what state produced the findings. The metadata
 * never carries a DSN or password, only connection-level facts.
 */
final readonly class RunMetadata
{
    /**
     * @param  list<ServerVersion>  $serverVersions  the addressed instance versions
     * @param  array<string, string>  $toolVersions  external tool name → version
     */
    public function __construct(
        public array $serverVersions,
        public array $toolVersions,
        public CaptureMode $mode,
        public string $profile,
        public bool $strictTools,
        public ?int $timeBudgetMsConsumed = null,
    ) {}

    /**
     * A deterministic array projection with a fixed key order. An absent time
     * budget is omitted rather than serialized as null.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $projection = [
            'server_versions' => array_map(
                static fn (ServerVersion $version): string => sprintf('%d.%d.%d', $version->major, $version->minor, $version->patch),
                $this->serverVersions,
            ),
            'tool_versions' => $this->toolVersions,
            'mode' => $this->mode->value,
            'profile' => $this->profile,
            'strict_tools' => $this->strictTools,
            'time_budget_ms_consumed' => $this->timeBudgetMsConsumed,
        ];

        return array_filter($projection, static fn (mixed $value): bool => $value !== null);
    }
}
