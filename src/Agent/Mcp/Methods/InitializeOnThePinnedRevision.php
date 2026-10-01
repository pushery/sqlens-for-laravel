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
 * Answers the handshake with the revision this build speaks, and never with one it does not.
 *
 * ## Version negotiation, as the protocol defines it
 *
 * The client asks for the revision it prefers. A server that speaks it answers with it; otherwise
 * it answers with a revision it does speak, and the client decides whether to continue (MCP
 * 2025-06-18, lifecycle, "Version Negotiation"). So a client that prefers a newer revision and also
 * speaks this one still connects, and one that speaks only the newer one disconnects on its side,
 * knowing why. The answer is the pinned revision either way, the same on every run:
 * {@see McpProtocol::VERSION} carries the reasoning for the pin itself.
 *
 * ## Why this class exists at all
 *
 * The SDK negotiates too, but against every revision IT knows: asked for a newer one it recognizes,
 * it answers with that one, from a build that implements `2025-06-18`. The client would get a
 * message shape it did not ask for and has no reason to doubt. So the SDK is handed the revision
 * this server chose, and what it answers is checked against that choice.
 *
 * ## Two refusals, and neither is about a revision the client prefers
 *
 * - **A `protocolVersion` that is not a string** is a malformed request, refused as invalid params
 *   with the supported revision named.
 * - **The SDK answers a revision other than the one chosen** is refused as an internal error,
 *   because at that point the build cannot keep its own promise. It is unreachable today and is
 *   exactly what went wrong once already: it turns the next such change into a loud failure on the
 *   first handshake rather than a schema nobody notices.
 */
final class InitializeOnThePinnedRevision extends Initialize
{
    #[Override]
    public function handle(JsonRpcRequest $request, ServerContext $context): JsonRpcResponse
    {
        $requested = $request->params['protocolVersion'] ?? null;
        $supported = $context->supportedProtocolVersions;

        // -32602 is JSON-RPC's INVALID_PARAMS: the frame is well formed and one of its values is
        // not one this server can read. The value is quoted back, because a refusal that does not
        // say what was refused makes a client guess at its own request.
        if (! is_string($requested)) {
            throw new JsonRpcException(
                sprintf(
                    'Invalid params: protocolVersion must be a revision string; this build speaks [%s], the client sent [%s].',
                    implode(', ', $supported),
                    is_scalar($requested) ? (string) $requested : get_debug_type($requested),
                ),
                -32602,
                $request->id,
            );
        }

        $chosen = in_array($requested, $supported, true) ? $requested : ($supported[0] ?? McpProtocol::VERSION);

        $response = parent::handle(
            new JsonRpcRequest($request->id, $request->method, [...$request->params, 'protocolVersion' => $chosen]),
            $context,
        );

        /** @var array<string, mixed> $result */
        $result = is_array($response->content['result'] ?? null) ? $response->content['result'] : [];
        $served = $result['protocolVersion'] ?? null;

        if ($served !== $chosen) {
            throw new JsonRpcException(
                sprintf(
                    'Internal error: the installed MCP SDK answered revision [%s] where this build speaks [%s]. '
                    .'The handshake is refused rather than served, because a server that announces a revision it '
                    .'does not implement is worse than one that will not start.',
                    is_scalar($served) ? (string) $served : get_debug_type($served),
                    $chosen,
                ),
                -32603,
                $request->id,
            );
        }

        return $response;
    }
}
