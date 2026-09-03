<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Pushery\SQLens\Agent\Mcp\Tools\ExplainRuleTool;
use Pushery\SQLens\Agent\Mcp\Tools\GetDebtLedgerTool;
use Pushery\SQLens\Agent\Mcp\Tools\GetFindingsTool;
use Pushery\SQLens\Agent\Mcp\Tools\LintPendingTool;
use Pushery\SQLens\Agent\Mcp\Tools\LintShadowTool;
use Pushery\SQLens\Agent\Mcp\Tools\PredeployTool;
use Pushery\SQLens\Agent\Mcp\Tools\SqlensTool;
use Pushery\SQLens\Config\ConfigSchema;

/**
 * The one place an MCP tool exists. What is not declared here is not a tool.
 *
 * ## Why the list is written out rather than discovered
 *
 * No directory scan, no interface reflection, no class built from a configuration value. Each of
 * those would make "what this server exposes" a property of the filesystem or of a file a project
 * edits — so a file appearing under a path, or a string appearing in a config, would grow the
 * attack surface with nobody deciding to. A new tool is a commit somebody reviewed.
 *
 * It is also what keeps two runs comparable. A discovered set depends on autoload order and on what
 * happens to be installed; a written one does not.
 *
 * ## The configuration FILTERS, it never extends
 *
 * `agent.mcp.tools` can turn a declared tool off, and can turn a declared MUTATING tool on. It
 * cannot bring a tool into existence: a name the configuration knows and this class does not is
 * refused by the config validator, and would be ignored here even if it were not.
 *
 * ## Why the listing is sorted
 *
 * `tools/list` is a report, and this package's reports are byte-identical over an unchanged world.
 * Two agent sessions against one project must not diff against each other because a registration
 * moved a line.
 */
final readonly class ToolRegistry
{
    /**
     * Every tool this build knows how to expose, by class.
     *
     * Shorter than {@see ConfigSchema::MCP_TOOL_NAMES} while the remaining tools are each still
     * their own piece of work, and the gap is visible rather than papered over. A shell that
     * answered nothing would be a tool an agent could call and get silence from, which is worse
     * than a tool that is honestly not there yet — so a name is configurable before it is real,
     * and the registry is what decides whether it exists.
     *
     * @var list<class-string<SqlensTool>>
     */
    public const array DECLARED = [
        ExplainRuleTool::class,
        GetDebtLedgerTool::class,
        GetFindingsTool::class,
        LintPendingTool::class,
        // Mutating, and therefore off unless a project names it. Declared here all the same: the
        // policy decides what SHIPS ON, this class decides what EXISTS, and a tool that existed only
        // when it was enabled could never be reported as "real, and switched off" to a caller that
        // asked for it.
        LintShadowTool::class,
        // Mutating for REACH rather than for writes: it reads and only reads, and it reads the
        // production database at the moment before a deploy. That is the decision a project makes
        // by name, not one a release makes for it.
        PredeployTool::class,
    ];

    /** @param list<SqlensTool> $tools */
    private function __construct(private array $tools) {}

    /**
     * The registry this build ships.
     *
     * Instances rather than class names, because a caller that resolved them itself would be a
     * second place deciding what a tool is.
     */
    public static function declared(): self
    {
        $tools = [];

        foreach (self::DECLARED as $class) {
            $tools[] = new $class;
        }

        return new self($tools);
    }

    /**
     * The registry a set of instances forms — the seam the tests and a future host use.
     *
     * @param  list<SqlensTool>  $tools
     */
    public static function of(array $tools): self
    {
        return new self($tools);
    }

    /**
     * The tools this configuration exposes, sorted by name.
     *
     * A tool the policy does not enable is absent from the listing entirely rather than listed as
     * disabled: a client that can see a tool will try it, and "declared but refused" is a round
     * trip that teaches an agent nothing it can act on.
     *
     * @return list<SqlensTool>
     */
    public function exposedTo(McpToolPolicy $policy): array
    {
        $exposed = array_values(array_filter(
            $this->tools,
            static fn (SqlensTool $tool): bool => $policy->isEnabled($tool->name()),
        ));

        usort($exposed, static fn (SqlensTool $a, SqlensTool $b): int => strcmp($a->name(), $b->name()));

        return $exposed;
    }

    /**
     * Every declared tool, sorted — what the registry holds, before any configuration.
     *
     * @return list<SqlensTool>
     */
    public function all(): array
    {
        $sorted = $this->tools;

        usort($sorted, static fn (SqlensTool $a, SqlensTool $b): int => strcmp($a->name(), $b->name()));

        return $sorted;
    }

    /**
     * The names a refusal should offer — every tool this build has, enabled or not.
     *
     * Deliberately the full set rather than the enabled one. An agent that called a real tool which
     * this project has switched off needs to hear that it exists and is off; a list that hid it
     * would send them looking for a spelling mistake they did not make.
     *
     * @return list<string>
     */
    public function names(): array
    {
        return array_map(static fn (SqlensTool $tool): string => $tool->name(), $this->all());
    }

    /**
     * Every declared name that the configuration surface does not know.
     *
     * Two lists of the same thing: this registry and {@see ConfigSchema::MCP_TOOL_NAMES}. A tool
     * declared here but absent there could never be configured — it would ship on with no way to
     * turn it off, which for a mutating tool is the failure this whole layer is arranged to
     * prevent.
     *
     * @return list<string>
     */
    public function namesUnknownToConfig(): array
    {
        return array_values(array_diff($this->names(), ConfigSchema::MCP_TOOL_NAMES));
    }
}
