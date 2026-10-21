<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * The one revision of the Model Context Protocol this build speaks.
 *
 * ## Why a pin and not a range
 *
 * Left to itself, the SDK answers the `initialize` handshake in whichever of its three revisions,
 * `2025-11-25`, `2025-06-18` and `2025-03-26`, the client asks for, and in `2025-11-25` when the
 * client asks for any other; its newer discovery handshake offers its `LATEST`, `2026-07-28`. The revision a session
 * speaks would then depend on the client and on the SDK release installed. That makes the protocol
 * a second thing that can differ between two runs over an unchanged database, and determinism is
 * one of this package's three principles: the same state must produce the same answer on a
 * developer's machine and in CI, whichever agent happens to be driving.
 *
 * The revisions named here are those of `laravel/mcp` 1.1.
 *
 * A client asking for another revision is answered with this one, as the protocol's version
 * negotiation requires, and decides itself whether to continue. It is never answered in a revision
 * this build does not implement: that would be a schema shape the client did not ask for and has
 * no reason to doubt, which is the quiet direction.
 *
 * ## Why this revision
 *
 * `2025-06-18` is what the ecosystem's clients actually speak today; the SDK's own `LATEST` and the
 * newest revision its `initialize` knows are both newer. Raising it is a deliberate change with a
 * measured transcript behind it, not a version bump — see the SDK spike note for what such a
 * measurement looks like.
 */
final readonly class McpProtocol
{
    /** The MCP revision this build implements. */
    public const string VERSION = '2025-06-18';

    /** The server name a client sees in `serverInfo`. */
    public const string SERVER_NAME = 'sqlens';
}
