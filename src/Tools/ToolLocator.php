<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Illuminate\Contracts\Config\Repository;

/**
 * Resolves each known tool to a diagnostic — the configured path first, then the
 * system `$PATH`, then a named absence. It reaches nothing on the network: it reads a
 * config value, inspects `$PATH`, and runs a local binary for its version, all through
 * the ProcessRunner seam.
 *
 * The precedence (config path → `$PATH`) is what lets a project pin a specific binary
 * for reproducibility while still working out of the box when the tool is simply
 * installed system-wide.
 *
 * A pinned path that does not run does NOT fall through to `$PATH`. That fall-through was
 * here, and it was the dangerous kind of helpful: the configuration would read as honored
 * while the verdict came from whichever binary happened to be installed. Naming a path is
 * a statement about WHICH binary, so a broken pin is reported, not worked around.
 *
 * Resolution is cached for the life of this instance — one run. The diagnostic is asked for
 * repeatedly (the run header, the doctor command, the strict-tool gate), and each miss used
 * to cost a fork for `--version`. The cache makes the answer both cheap and identical to
 * itself within a run, which matters more: two readings that disagree would be worse than
 * two readings that are slow.
 */
final class ToolLocator
{
    /** @var array<string, ToolDiagnostic> keyed by tool name — one resolution per run. */
    private array $resolved = [];

    public function __construct(
        private readonly ProcessRunner $runner,
        private readonly Repository $config,
        private readonly KnownTools $known,
    ) {}

    /**
     * A diagnostic for every known tool, in registration order. Empty until a tool
     * adapter registers — and an empty list is the honest "no external tools", never a
     * silent absence.
     *
     * @return list<ToolDiagnostic>
     */
    public function diagnoseAll(): array
    {
        return array_map($this->diagnose(...), $this->known->tools);
    }

    /**
     * A diagnostic for every known tool that has jurisdiction over this driver — the view a RUN
     * needs, as opposed to the machine-wide view {@see diagnoseAll()} gives the doctor.
     *
     * The tools that do not apply are *absent*, not reported as degraded. That is the whole point
     * of the split: a run must not name a loss it never had, and — because the same list feeds
     * the strict gate — a PostgreSQL-only tool listed on a MySQL run would fail that project's
     * strict build for an install that could not have helped it.
     *
     * Filtering here, once, rather than at each consumer: the list is read by the header, the
     * strict gate and the notice loop, and a filter applied at three call sites is a filter with
     * two chances to be forgotten.
     *
     * @return list<ToolDiagnostic>
     */
    public function diagnoseFor(string $driver): array
    {
        return array_values(array_filter(
            $this->diagnoseAll(),
            static fn (ToolDiagnostic $diagnostic): bool => $diagnostic->tool->supportsDriver($driver),
        ));
    }

    public function diagnose(Tool $tool): ToolDiagnostic
    {
        return $this->resolved[$tool->name()] ??= $this->resolve($tool);
    }

    private function resolve(Tool $tool): ToolDiagnostic
    {
        // The project's own decision, read before anything else — including before the platform
        // check and before any process starts. A run that has been told not to use a tool must not
        // spend a fork finding out where it is, and must not report on a build it was never going
        // to run.
        if ($this->config->get('sqlens.tools.'.$tool->name().'.enabled') === false) {
            return new ToolDiagnostic($tool, ToolResolution::Disabled);
        }

        // A tool with no build for this platform degrades with a named reason — never a
        // strict failure for something it could never have had.
        if (! $tool->supportsCurrentPlatform()) {
            return new ToolDiagnostic($tool, ToolResolution::UnsupportedPlatform);
        }

        $configured = $this->config->get('sqlens.tools.'.$tool->name().'.path');

        if (is_string($configured) && $configured !== '') {
            $version = $this->runner->version($configured);

            // No fall-through to `$PATH`. The project named this binary; if it does not answer,
            // the honest report is that the pin is broken — not a silent substitution.
            return $version !== null
                ? $this->versionChecked($tool, ToolResolution::ConfiguredPath, $configured, $version)
                : new ToolDiagnostic($tool, ToolResolution::ConfiguredPathNotExecutable, $configured);
        }

        $path = $this->runner->locate($tool->binaryName());

        if ($path !== null) {
            return $this->versionChecked($tool, ToolResolution::SystemPath, $path, $this->runner->version($path));
        }

        return new ToolDiagnostic($tool, ToolResolution::NotFound);
    }

    /**
     * The version gate, applied to a binary that was found — wherever it was found.
     *
     * It sits here rather than in each adapter because this is the only place both halves
     * meet: a check that lived in the adapter would be a check with no caller, and finding a
     * binary is exactly half of establishing that a tool can be used. The other half is
     * knowing WHICH binary answered, and an amplifier whose output shape is unverified is not
     * a weaker amplifier — it is a confident wrong answer.
     *
     * The path and the raw version line travel even when the verdict is a downgrade. A user
     * told "the version is wrong" needs to see which file said so and what it said; "wrong,
     * somewhere" is not actionable.
     */
    private function versionChecked(Tool $tool, ToolResolution $found, string $path, ?string $version): ToolDiagnostic
    {
        return new ToolDiagnostic($tool, match ($tool->verifyVersion($version)) {
            ToolVersionSupport::Supported => $found,
            ToolVersionSupport::Unreadable => ToolResolution::VersionUnreadable,
            ToolVersionSupport::OutOfWindow => ToolResolution::VersionUnsupported,
        }, $path, $version);
    }
}
