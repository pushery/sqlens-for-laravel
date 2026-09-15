<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Methods;

use Laravel\Mcp\Exceptions\JsonRpcException;
use Laravel\Mcp\Server\Methods\Initialize;
use Laravel\Mcp\Server\ServerContext;
use Laravel\Mcp\Transport\JsonRpcRequest;
use Laravel\Mcp\Transport\JsonRpcResponse;
use Override;
use Pushery\SQLens\Agent\Mcp\McpProtocol;

/**
 * Holds the handshake to the one revision this build speaks, instead of negotiating one it does not.
 *
 * ## Why this class exists at all
 *
 * The SDK used to refuse a revision the server had not declared. Since `laravel/mcp` 1.0 its own
 * `initialize` NEGOTIATES: a request for anything it does not recognize is answered with the newest
 * revision the SDK knows, and the server's declared pin is read only on the newer discovery
 * handshake. So an upgrade alone turned a refusal into a best-effort answer — `2025-11-25` to a
 * client that asked for something else, from a build that implements `2025-06-18`.
 *
 * That is the quiet direction, and it is the exact failure this package's pin was written against:
 * the client gets a message shape it did not ask for, cannot check, and has no reason to doubt.
 * {@see McpProtocol::VERSION} carries the reasoning for the pin itself.
 *
 * ## Two refusals, because there are two ways to serve the wrong revision
 *
 * - **The client asks for a revision this build does not speak** — refused by NAME, with the
 *   supported revision in the refusal, so the client can say what it did wrong and pick again.
 * - **The SDK answers a revision other than the one asked for** — refused as an internal error,
 *   because at that point the build cannot keep its own promise. This arm is unreachable today and
 *   is exactly what went wrong once already: it turns the next such change into a loud failure on
 *   the first handshake rather than a schema nobody notices.
 */
final class InitializeOnThePinnedRevision extends Initialize
{
    #[Override]
    public function handle(JsonRpcRequest $request, ServerContext $context): JsonRpcResponse
    {
        $requested = $request->params['protocolVersion'] ?? null;
        $supported = $context->supportedProtocolVersions;

        // -32602 is JSON-RPC's INVALID_PARAMS: the frame is well formed and one of its values is
        // not one this server accepts. The requested value is quoted back because a refusal that
        // does not say what was refused makes a client guess at its own request.
        if (! is_string($requested) || ! in_array($requested, $supported, true)) {
            throw new JsonRpcException(
                sprintf(
                    'Invalid params: this build speaks MCP revision [%s] and no other; the client asked for [%s]. '
                    .'Ask for the supported revision — a best-effort answer here would be a message shape the '
                    .'client did not ask for and cannot check.',
                    implode(', ', $supported),
                    is_scalar($requested) ? (string) $requested : get_debug_type($requested),
                ),
                -32602,
                $request->id,
            );
        }

        $response = parent::handle($request, $context);

        /** @var array<string, mixed> $result */
        $result = is_array($response->content['result'] ?? null) ? $response->content['result'] : [];
        $served = $result['protocolVersion'] ?? null;

        if ($served !== $requested) {
            throw new JsonRpcException(
                sprintf(
                    'Internal error: the installed MCP SDK answered revision [%s] where this build speaks [%s]. '
                    .'The handshake is refused rather than served, because a server that announces a revision it '
                    .'does not implement is worse than one that will not start.',
                    is_scalar($served) ? (string) $served : get_debug_type($served),
                    $requested,
                ),
                -32603,
                $request->id,
            );
        }

        return $response;
    }
}
