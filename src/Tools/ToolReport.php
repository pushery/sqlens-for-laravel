<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * What `sqlens:doctor` says about the external tools — assembled here so the command stays a
 * renderer and a second tool never needs it changed.
 *
 * The line that matters is not "found" or "not found". It is what the reader LOSES: a diagnostic
 * that reports an absence without naming its cost invites the reader to shrug, and the whole
 * reason to report an optional tool at all is that its absence is otherwise invisible.
 */
final readonly class ToolReport
{
    public function __construct(private ToolLocator $locator) {}

    /**
     * One entry per known tool, in registration order, with everything the renderer needs.
     *
     * Deterministic by construction: no timestamp, no absolute path beyond the resolved binary,
     * and the version is the one MEASURED rather than the one configured — a doctor that echoed
     * a configured assumption would confirm the configuration rather than the machine.
     *
     * @return list<array{name: string, resolution: string, available: bool, version: string|null,
     *                    path: string|null, adds: string, missing_checks: int}>
     */
    public function entries(): array
    {
        return array_map(
            static fn (ToolDiagnostic $diagnostic): array => [
                'name' => $diagnostic->tool->name(),
                'resolution' => $diagnostic->resolution->value,
                'available' => $diagnostic->isAvailable(),
                'version' => $diagnostic->version,
                // The path only when something WAS found. Printing a configured path that resolved
                // to nothing would read as "it is here", which is the opposite of the finding.
                'path' => $diagnostic->isAvailable() ? $diagnostic->path : null,
                'adds' => $diagnostic->tool->whatItEnables(),
                // How many checks are simply absent without it. A count is what makes an absence
                // arguable: "not installed" invites a shrug, "17 checks nobody is running" does not.
                'missing_checks' => $diagnostic->isAvailable() ? 0 : $diagnostic->tool->uncoveredCheckCount(),
            ],
            $this->locator->diagnoseAll(),
        );
    }
}
