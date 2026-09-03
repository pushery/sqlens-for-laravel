<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Illuminate\Contracts\Config\Repository;
use Laravel\Mcp\Server;
use Pushery\SQLens\Agent\Mcp\Transport\SqlensStdioTransport;
use Throwable;

/**
 * The real stdio conversation: build the transport, start the server, read frames until EOF.
 *
 * ## Why this is its own file
 *
 * It is excluded from the coverage gate, and the exclusion holds on two conditions rather than one:
 * every statement here is per-PROCESS wiring — a shield, a signal listener, a shutdown reporter, a
 * transport over the real streams — and a REAL SUBPROCESS proves the lot of it —
 * `tests/Feature/Agent/McpStdioSubprocessTest.php` starts the actual command with actual JSON-RPC
 * frames on its stdin and reads the frames that come back. No in-process coverage run can observe
 * that, and no in-process run can drive this method either: `run()` takes over STDIN, so calling
 * it from a test runner would hand the runner's own stdin to the loop.
 *
 * The subprocess arms cover each ending: a client that closes, a SIGTERM, a SIGINT, and a session
 * whose whole standard output is parsed line by line. What each of them USES — the shield, the
 * shutdown request, the exit reasons, the transport — is ordinary covered code with tests of its
 * own. Nothing that makes a decision lives here; this file only puts the pieces on the process.
 *
 * Everything that CAN be exercised in process — the guards, the exit codes, the operator's line —
 * lives in the command instead, behind {@see ServesMcp}. The split is what keeps the exclusion
 * three lines wide rather than a whole command.
 *
 * ## Why nothing here is configurable
 *
 * The transport is the one this build speaks and the server is the one this package ships. A
 * choice at this point would be a second place where "which server, on which transport" is
 * decided, and the configuration already decides it.
 */
final class StdioServerLoop implements ServesMcp
{
    /** @var list<string> tools this session enabled by name, from `--enable-tool` */
    private array $sessionEnables = [];

    public function __construct(private readonly Repository $config, private readonly StdoutShield $shield) {}

    /**
     * The policy for this session.
     *
     * Built from the configuration plus whatever this run enabled by name — and only when nothing
     * has bound one already. The command binds it before serving, so the listing and the
     * `tools/call` handler read the SAME object; this fallback exists for a host that resolves the
     * loop some other way, and it must not silently disagree with the command when both ran.
     */
    private function policy(): McpToolPolicy
    {
        return McpToolPolicy::fromConfig($this->config->get('sqlens.agent.mcp.tools'))
            ->alsoEnabling($this->sessionEnables);
    }

    /**
     * Enable these tools for this run, one name at a time.
     *
     * Separate from the configuration on purpose: the config says what a PROJECT has adopted, this
     * says what an operator is doing in THIS session. There is no "all" — see
     * {@see McpToolPolicy::alsoEnabling()}.
     *
     * @param  list<string>  $tools
     */
    public function enableForSession(array $tools): void
    {
        $this->sessionEnables = $tools;
    }

    public function isAvailable(): bool
    {
        return class_exists(Server::class);
    }

    public function serve(): McpExit
    {
        // Up already, if the service provider saw this command in the arguments. Called again here
        // because the loop must not depend on that having happened — an application that resolves
        // this class some other way still gets a clean channel.
        $this->shield->engage();

        // A fatal never reaches the error handler, and it is the one message a user most needs:
        // without it the process dies with an empty stream and the client reports only "server
        // disconnected".
        //
        // Registered HERE rather than inside the shield, and the placement is the point. A shutdown
        // function cannot be unregistered, so putting it beside the output buffer would leave one
        // behind for every engage/release cycle. This file is the one place a process really is a
        // server — and the one place a per-process registration belongs. What it calls,
        // `reportFatal()`, is ordinary covered code.
        $shield = $this->shield;

        register_shutdown_function(static function () use ($shield): void {
            $shield->reportFatal(error_get_last());
        });

        // A fresh identifier per conversation. The SDK's own local-server registration does the
        // same; it is generated here rather than taken from anywhere durable because a session is
        // exactly one client conversation and outlives nothing.
        //
        // The transport is OURS rather than the SDK's, and the reason is testability plus one real
        // gap: the SDK writes a frame with a single `fwrite()` and never looks at how many bytes it
        // took, which on a socket loses the remainder silently. See the transport's own docblock.
        // Signals become a REQUEST the loop reads between frames, never an exit from inside a
        // handler: a signal can land halfway through a write, and leaving a half-written message on
        // the wire is a client parser that never recovers.
        $shutdown = new ShutdownRequest;
        ShutdownSignals::install($shutdown, STDERR);

        $transport = new SqlensStdioTransport(bin2hex(random_bytes(16)), STDIN, STDOUT, $shutdown);

        // The registry decides what exists; the policy decides what this project exposes. The
        // server is handed the answer rather than either of the two questions — it must not be a
        // third place where "which tools" is decided.
        // The policy the COMMAND already bound, read back rather than rebuilt. Building a second one
        // here would be a second answer about which tools are on — and the `tools/call` handler
        // resolves the bound one, so the two would decide differently about the same session.
        $exposed = ToolRegistry::declared()->exposedTo($this->policy());

        new SqlensMcpServer($transport, $exposed)->start();

        try {
            $transport->run();
        } catch (Throwable $failure) {
            // A broken run is an ending too, and it says so on the diagnostic channel before the
            // named reason follows. Swallowing it would produce the silent exit this whole ticket
            // exists to make impossible.
            fwrite(STDERR, '[sqlens:mcp] '.$failure::class.': '.$failure->getMessage().PHP_EOL);

            return McpExit::Failed;
        }

        return $shutdown->reason() ?? McpExit::ClientClosed;
    }
}
