<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * What the locator found for one tool: whether it is available, where, at what
 * version, and — when it is not — the named reason. This is the unit the run header
 * reports and the strict/non-strict decision reads.
 *
 * Deterministic by construction: it carries no timestamp and no absolute path beyond
 * the resolved binary path (which the reporter is free to omit), so the same
 * environment produces the same diagnostic.
 */
final readonly class ToolDiagnostic
{
    public function __construct(
        public Tool $tool,
        public ToolResolution $resolution,
        public ?string $path = null,
        public ?string $version = null,
    ) {}

    /** A tool found and runnable — its version belongs in the header. */
    public function isAvailable(): bool
    {
        return $this->resolution->isAvailable();
    }

    /** A fixable absence that a strict run must treat as an error. */
    public function failsStrict(): bool
    {
        return $this->resolution->failsStrict();
    }

    /**
     * Any absence a run must NAME — a not-found, a broken pin, an unreadable or unmeasured
     * version, or a platform with no build.
     *
     * A tool the project switched off is deliberately not one of them. It is unavailable, and it
     * is not missing: the difference between "SQLens could not use this" and "you told SQLens not
     * to" is the difference between a finding worth reading and a finding that trains people to
     * skim.
     */
    public function isMissing(): bool
    {
        return ! $this->isAvailable() && $this->resolution !== ToolResolution::Disabled;
    }

    /**
     * A stable projection for the run header, in a fixed key order.
     *
     * @return array{name: string, resolution: string, version: string|null}
     */
    public function toArray(): array
    {
        return [
            'name' => $this->tool->name(),
            'resolution' => $this->resolution->value,
            'version' => $this->version,
        ];
    }
}
