<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Methods;

use Generator;
use Illuminate\Database\DatabaseManager;
use Laravel\Mcp\Exceptions\JsonRpcException;
use Laravel\Mcp\Server\Methods\CallTool;
use Laravel\Mcp\Server\ServerContext;
use Laravel\Mcp\Server\Tool;
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
 * So a declared-but-disabled tool is refused by name, with the two ways to enable it. A name
 * nothing declares still comes back not-found, from the SDK's own handler, because that answer is
 * correct for it.
 *
 * ## Why it does not decide anything
 *
 * The policy decides; this reads it. The opt-in check lives in exactly one place — the registry
 * filter that builds the exposed set — and a second decision here would be a second answer about
 * which tools are on, free to disagree with the listing a client already holds.
 *
 * ## Why it looks the tool up itself
 *
 * The SDK's handler does the same lookup and hands the tool to an invoker it builds itself, one that
 * answers a failure with the exception's message whenever the application runs with `app.debug` on.
 * The lookup is repeated here so the tool reaches {@see WithholdingToolInvoker} instead, which answers
 * with what failed and keeps the message out of the answer.
 *
 * ## Why it closes what a call opened
 *
 * A tool opens the connections it needs inside the services it reaches, and the database manager
 * keeps each one it has resolved. In the CLI the process ends and takes them along; in this one
 * they would stay for the rest of the editor session, idle, on a machine that may be pointed at
 * production. So every connection the call added is closed once the call is answered, and one
 * that was open before it is left alone, because it is not the call's.
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
    public function __construct(
        private readonly McpToolPolicy $policy,
        private readonly ToolRegistry $registry,
        private readonly DatabaseManager $database,
    ) {}

    #[Override]
    public function handle(JsonRpcRequest $request, ServerContext $context): Generator|JsonRpcResponse
    {
        $name = $request->params['name'] ?? null;
        $refusal = is_string($name) ? $this->refusalFor($name) : null;

        // -32602, the code the SDK and the specification give a tool name that cannot be called, and
        // never -32601, which says the METHOD does not exist. The state travels as data, so a client
        // tells a switched-off tool from an unbuilt one without reading the sentence.
        if (is_array($refusal)) {
            throw new JsonRpcException($refusal['message'], -32602, $request->id, ['tool' => $name, 'state' => $refusal['state']]);
        }

        if ($name === null) {
            throw new JsonRpcException('Missing [name] parameter.', -32602, $request->id);
        }

        $tool = $context->tools()->first(
            static fn (Tool $tool): bool => $tool->name() === $name,
            static fn () => throw new JsonRpcException(sprintf('Tool [%s] not found.', is_scalar($name) ? (string) $name : get_debug_type($name)), -32602, $request->id),
        );

        $open = array_keys($this->database->getConnections());

        // Every tool of this package answers at once, so the call's work is done when invoke()
        // returns, and `finally` closes its connections whether it answered or threw.
        try {
            return new WithholdingToolInvoker()->invoke($tool, $request);
        } finally {
            foreach (array_diff(array_keys($this->database->getConnections()), $open) as $opened) {
                $this->database->purge($opened);
            }
        }
    }

    /**
     * Why this name cannot be called, or null when it can be.
     *
     * Three answers, not two, because there are three states and collapsing any pair of them tells
     * somebody something untrue:
     *
     * - **built and switched off** — the capability is here and this project has not enabled it.
     *   The refusal names both ways to turn it on.
     * - **named but not built** — the configuration surface knows it, so a project can already
     *   write it into a file, and this build has no such tool. Saying "not enabled" here would send
     *   somebody to flip a switch that changes nothing.
     * - **neither** — a typo or an invention, and the SDK's own "not found" is the right answer.
     *
     * @return array{message: string, state: 'disabled'|'reserved'}|null
     */
    private function refusalFor(string $name): ?array
    {
        if (in_array($name, $this->registry->names(), true)) {
            return $this->policy->isEnabled($name) ? null : ['state' => 'disabled', 'message' => sprintf(
                'Tool [%s] exists in this build and is not enabled on this project. Enable it by name — '
                .'set sqlens.agent.mcp.tools.%s to true, or start the server with --enable-tool=%s. '
                .'There is no switch that enables every tool at once.',
                $name,
                $name,
                $name,
            )];
        }

        if (in_array($name, ConfigSchema::MCP_TOOL_NAMES, true)) {
            return ['state' => 'reserved', 'message' => sprintf(
                'Tool [%s] is a name this package reserves and this build does not implement yet. Enabling it '
                .'in configuration changes nothing until it ships.',
                $name,
            )];
        }

        return null;
    }
}
