<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * The thing that actually holds a client conversation, behind a contract the command can address.
 *
 * ## Why the command does not just build the loop itself
 *
 * Serving means handing this process's STDIN to a read loop that ends at EOF. That is exactly
 * right for a server and impossible to drive from inside a test runner: the loop would take the
 * runner's own stdin, and what the assertions measured would be the runner rather than the server.
 * So the loop lives behind this contract, is proved as a REAL SUBPROCESS with real frames, and the
 * command — the guards, the exit codes, the operator's line — stays ordinary testable code.
 *
 * ## Why availability is a question and not an assumption
 *
 * `laravel/mcp` is optional. It genuinely may not be installed, and the difference between "not
 * installed" and "broken" has to reach the operator as a sentence rather than as a class-not-found
 * trace. Asking here rather than in the command keeps the command free of the SDK's names, which
 * is what lets it be constructed and tested on a machine that does not have it.
 */
interface ServesMcp
{
    /**
     * Enable these tools for this run, by name.
     *
     * On the contract rather than on the implementation because it is the OPERATOR's half of the
     * opt-in, and a command must be able to pass it without knowing which loop it is talking to.
     * There is no "all" and there will not be one: a master switch turns a decision about one
     * dangerous capability into a decision about every dangerous capability this package will ever
     * have, including the ones added after somebody flipped it.
     *
     * @param  list<string>  $tools
     */
    public function enableForSession(array $tools): void;

    /** Whether the optional server SDK is installed in this application. */
    public function isAvailable(): bool;

    /**
     * Hold the conversation until it ends, and say how it ended.
     *
     * Returns the named reason rather than nothing, because a silent exit 0 is the cardinal failure
     * of this surface: it reads to every log reader as a clean end, and it is exactly the signature
     * a read timeout mistaken for a hangup produced. Every way out of a run has a name.
     */
    public function serve(): McpExit;
}
