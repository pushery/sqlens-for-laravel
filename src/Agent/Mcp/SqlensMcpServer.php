<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Laravel\Mcp\Server;
use Laravel\Mcp\Server\Contracts\Transport;
use Laravel\Mcp\Server\Tool;
use Pushery\SQLens\Agent\Mcp\Methods\CallDeclaredTool;
use Pushery\SQLens\Agent\Mcp\Tools\SqlensTool;
use Pushery\SQLens\PackageVersion;
use stdClass;

/**
 * The MCP server SQLens exposes — a thin shell, and nothing else.
 *
 * It carries no rule logic, no capture logic and no catalog logic. Every tool hung on it later is
 * an adapter over a command that already exists, so a question asked over MCP and the same
 * question asked on the command line cannot answer differently about one database. The parity
 * harness is what keeps that true; this class is what makes it possible, by having nowhere to put
 * a second implementation.
 *
 * ## Why the capability list is this short
 *
 * One capability: `tools`. The SDK's default also declares `resources` and `prompts`, and each of
 * those is a surface a client can call. An MCP server is an attack surface, so a capability is
 * declared when something behind it exists and is wanted — never because the default offered it.
 * Nothing here serves resources or prompts, and announcing that it might is an invitation with no
 * building behind it.
 *
 * ## Why there are no tools yet
 *
 * The registry is its own piece of work. A server that can hold the handshake, refuse a protocol
 * revision it does not speak, and name itself honestly is a complete thing to prove on its own —
 * and proving it before any tool exists means the tools are added to something already known to
 * behave.
 *
 * ## Why it opens nothing
 *
 * Starting the server touches no database. Connections are opened INSIDE the services a tool call
 * reaches, for the length of that call, exactly as the CLI does it — a server holding an open
 * connection for the lifetime of an editor session would be a connection nobody asked for on a
 * machine that may be pointed at production.
 */
final class SqlensMcpServer extends Server
{
    protected string $name = McpProtocol::SERVER_NAME;

    protected string $instructions = <<<'MARKDOWN'
        SQLens answers questions about what a database migration will do, deterministically and
        without running it against production. Ask it instead of guessing: the same question always
        gets the same answer, and an answer it cannot determine says so rather than passing.
        MARKDOWN;

    /**
     * Pinned to one revision. See {@see McpProtocol::VERSION} for why a range would cost
     * determinism.
     *
     * @var array<int, string>
     */
    protected array $supportedProtocolVersion = [McpProtocol::VERSION];

    /** @var array<string, array<string, bool>|stdClass|string> */
    protected array $capabilities = [
        self::CAPABILITY_TOOLS => ['listChanged' => false],
    ];

    /**
     * The tools this server exposes, as INSTANCES the registry already filtered and sorted.
     *
     * Filled in the constructor rather than declared as a class list, and the difference is the
     * point: a class list here would be a second declaration of what exists, next to the registry's
     * — and the configuration could then be honored in one of them and not the other.
     *
     * @var array<int, Tool|class-string<Tool>>
     */
    protected array $tools;

    /** @param  list<SqlensTool>  $tools */
    public function __construct(Transport $transport, array $tools = [])
    {
        parent::__construct($transport);

        $this->tools = $tools;

        // A call to a DECLARED but disabled tool is refused by name rather than called unknown.
        // Without this the SDK answers "not found" for both, which tells an agent that a real
        // capability does not exist and sends a log reader looking for a typo that is not there.
        $this->addMethod('tools/call', CallDeclaredTool::class);

        // Read from Composer's installed set rather than declared as a second string here. A
        // hand-maintained version drifts from the released one silently, and `serverInfo` is the
        // one place a client learns which build it is talking to — a wrong answer there sends a
        // bug report to the wrong version.
        $this->version = PackageVersion::current();
    }
}
