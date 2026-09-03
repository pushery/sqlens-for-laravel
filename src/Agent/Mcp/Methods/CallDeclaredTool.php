<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Methods;

use Generator;
use Laravel\Mcp\Exceptions\JsonRpcException;
use Laravel\Mcp\Server\Methods\CallTool;
use Laravel\Mcp\Server\ServerContext;
use Laravel\Mcp\Transport\JsonRpcRequest;
use Laravel\Mcp\Transport\JsonRpcResponse;
use Override;
use Pushery\SQLens\Agent\Mcp\McpToolPolicy;
use Pushery\SQLens\Agent\Mcp\ToolRegistry;
use Pushery\SQLens\Config\ConfigSchema;

/**
 * Answers a call to a tool that EXISTS but is switched off, instead of calling it unknown.
 *
 * ## Why the two are told apart
 *
 * Without this, a disabled tool and a misspelt one give the same answer: "not found". That is a
 * quiet lie in both directions. An agent that asked for `predeploy` on a project which has not
 * enabled it would conclude the capability does not exist and stop asking — and the person reading
 * the log would go looking for a typo that is not there. Obscuring a real capability is a form of
 * silent green: the answer is comfortable and wrong.
 *
 * So a declared-but-disabled tool is refused BY NAME, with the two ways to enable it. A name
 * nothing declares still comes back not-found, from the SDK's own handler, because that answer is
 * correct for it.
 *
 * ## Why it does not decide anything
 *
 * The policy decides; this reads it. The opt-in check lives in exactly one place — the registry
 * filter that builds the exposed set — and a second decision here would be a second answer about
 * which tools are on, free to disagree with the listing a client already holds.
 */
final class CallDeclaredTool extends CallTool
{
    /**
     * The registry arrives as a dependency rather than through `ToolRegistry::declared()`.
     *
     * It used to be the static call, and that made the "reserved but not implemented" arm below
     * UNREACHABLE the day the last reserved name shipped: with the registry fixed to what this build
     * declares, no name can be in the configuration surface and absent from it. A branch nothing can
     * enter reads exactly like a branch that works, and this one carries a message a project would
     * otherwise never see again.
     */
    public function __construct(private readonly McpToolPolicy $policy, private readonly ToolRegistry $registry) {}

    #[Override]
    public function handle(JsonRpcRequest $request, ServerContext $context): Generator|JsonRpcResponse
    {
        $name = $request->params['name'] ?? null;
        $refusal = is_string($name) ? $this->refusalFor($name) : null;

        if (is_string($refusal)) {
            throw new JsonRpcException($refusal, -32601, $request->id);
        }

        return parent::handle($request, $context);
    }

    /**
     * Why this name cannot be called, or null when it can be.
     *
     * THREE answers, not two, because there are three states and collapsing any pair of them tells
     * somebody something untrue:
     *
     * - **built and switched off** — the capability is here and this project has not enabled it.
     *   The refusal names both ways to turn it on.
     * - **named but not built** — the configuration surface knows it, so a project can already
     *   write it into a file, and this build has no such tool. Saying "not enabled" here would send
     *   somebody to flip a switch that changes nothing.
     * - **neither** — a typo or an invention, and the SDK's own "not found" is the right answer.
     */
    private function refusalFor(string $name): ?string
    {
        if (in_array($name, $this->registry->names(), true)) {
            return $this->policy->isEnabled($name) ? null : sprintf(
                'Tool [%s] exists in this build and is not enabled on this project. Enable it by name — '
                .'set sqlens.agent.mcp.tools.%s to true, or start the server with --enable-tool=%s. '
                .'There is no switch that enables every tool at once.',
                $name,
                $name,
                $name,
            );
        }

        if (in_array($name, ConfigSchema::MCP_TOOL_NAMES, true)) {
            return sprintf(
                'Tool [%s] is a name this package reserves and this build does not implement yet. Enabling it '
                .'in configuration changes nothing until it ships.',
                $name,
            );
        }

        return null;
    }
}
