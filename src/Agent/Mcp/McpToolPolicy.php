<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Pushery\SQLens\Config\ConfigSchema;

/**
 * Which MCP tools a project has exposed — the one reader of `agent.mcp.tools`.
 *
 * ## Why absence is answered here rather than by the config merge
 *
 * `mergeConfigFrom()` is a shallow merge, so a project that published `config/sqlens.php` before a
 * release added a tool has no entry for it — not `false`, absent. Somewhere has to decide what
 * that means, and the decision is asymmetric on purpose:
 *
 * - a **read-only** tool absent from the map takes the shipped default, which is on. It reads and
 *   never writes; a project that upgraded should get the new reader without editing a file.
 * - a **mutating** tool absent from the map is **off**, always. "Not mentioned" must never mean
 *   "allowed": a release that added `predeploy` would otherwise switch it on in every project
 *   whose config predates it, and the first anybody heard of it would be a deploy gate they never
 *   enabled.
 *
 * That is why {@see ConfigSchema::MCP_MUTATING_TOOLS} is a declared list rather than something
 * derived from the shipped defaults. The defaults live in a file a project edits; which tools are
 * dangerous must not be answerable by editing that file.
 *
 * ## Why an unknown name is false rather than an error
 *
 * The configuration validator has already refused an unknown name with the list of real ones, and
 * refused it loudly enough to stop the run. Reaching this class with one means the validator was
 * bypassed — and the safe answer to "should I expose a tool I have never heard of" is no.
 */
final readonly class McpToolPolicy
{
    /** @param array<string, bool> $switches every KNOWN tool name that the configuration mentions */
    private function __construct(private array $switches) {}

    /**
     * The policy a configuration expresses.
     *
     * Takes `mixed` and narrows here rather than asking every caller to: the value arrives from
     * `config()`, and a second narrowing beside a second caller would be a second answer about
     * one file.
     */
    public static function fromConfig(mixed $configured): self
    {
        $switches = [];
        $map = is_array($configured) ? $configured : [];

        foreach ($map as $name => $enabled) {
            $name = (string) $name;

            if (in_array($name, ConfigSchema::MCP_TOOL_NAMES, true) && is_bool($enabled)) {
                $switches[$name] = $enabled;
            }
        }

        return new self($switches);
    }

    /**
     * The same policy with these tools additionally on — one name at a time.
     *
     * The second of the two sanctioned ways to enable a tool, and the reason it exists beside the
     * configuration is that they answer different questions. The config says what a PROJECT has
     * adopted; this says what an operator is doing in THIS session, which is how somebody tries a
     * mutating tool once without leaving it on in a file everybody shares.
     *
     * There is no version of this that takes "all". Every enable names its tool, here and in the
     * configuration, because a master switch turns a decision about one dangerous capability into a
     * decision about every dangerous capability the package will ever have — including the ones
     * added after somebody flipped it.
     *
     * A name this build does not know is IGNORED rather than accepted. The command refuses it
     * loudly first; reaching here with one means that refusal was bypassed, and the safe answer to
     * "enable a tool I have never heard of" is no.
     *
     * @param  list<string>  $tools
     */
    public function alsoEnabling(array $tools): self
    {
        $switches = $this->switches;

        foreach ($tools as $tool) {
            if (in_array($tool, ConfigSchema::MCP_TOOL_NAMES, true)) {
                $switches[$tool] = true;
            }
        }

        return new self($switches);
    }

    /**
     * The enabled tools that CHANGE something.
     *
     * Read from the tool contract's own `mutating` answer wherever a tool object is in hand; here
     * the schema's declared set is the source, because a policy is a set of names and knows no
     * classes. The two are held together by the registry arm that refuses a declared tool the
     * configuration surface does not know.
     *
     * @return list<string>
     */
    public function enabledMutating(): array
    {
        return array_values(array_filter(
            $this->enabled(),
            static fn (string $tool): bool => in_array($tool, ConfigSchema::MCP_MUTATING_TOOLS, true),
        ));
    }

    /** Whether the server exposes this tool. */
    public function isEnabled(string $tool): bool
    {
        if (! in_array($tool, ConfigSchema::MCP_TOOL_NAMES, true)) {
            return false;
        }

        return $this->switches[$tool] ?? ! in_array($tool, ConfigSchema::MCP_MUTATING_TOOLS, true);
    }

    /**
     * Every exposed tool, in the schema's declared order.
     *
     * The order is the schema's rather than the configuration's, because `tools/list` is a report
     * and this package's reports are byte-identical over an unchanged world. A project that
     * happened to write its map in a different order must not produce a different listing.
     *
     * @return list<string>
     */
    public function enabled(): array
    {
        return array_values(array_filter(
            ConfigSchema::MCP_TOOL_NAMES,
            $this->isEnabled(...),
        ));
    }
}
