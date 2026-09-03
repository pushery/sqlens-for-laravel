<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * The one revision of the Model Context Protocol this build speaks.
 *
 * ## Why a pin and not a range
 *
 * The SDK's default is every revision it knows — four of them — and a server that offers all four
 * speaks whichever one the client happens to ask for. That makes the protocol a second thing that
 * can differ between two runs over an unchanged database, and determinism is one of this package's
 * three principles: the same state must produce the same answer on a developer's machine and in
 * CI, whichever agent happens to be driving.
 *
 * A client asking for anything else is refused by NAME, with the supported revision in the
 * refusal, rather than served best-effort. Best-effort here means answering a schema shape the
 * client did not ask for and cannot check, which is the quiet direction.
 *
 * ## Why this revision
 *
 * `2025-06-18` is what the ecosystem's clients actually speak today; the SDK's own `LATEST` is
 * newer. Raising it is a deliberate change with a measured transcript behind it, not a version
 * bump — see the SDK spike note for what such a measurement looks like.
 */
final readonly class McpProtocol
{
    /** The MCP revision this build implements. */
    public const string VERSION = '2025-06-18';

    /** The server name a client sees in `serverInfo`. */
    public const string SERVER_NAME = 'sqlens';
}
