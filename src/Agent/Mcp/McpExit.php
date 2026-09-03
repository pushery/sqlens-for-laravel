<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * Why an MCP server run ended, and what the process says about it.
 *
 * ## Why every ending is named
 *
 * A silent exit 0 is the cardinal failure of this surface. It reads to every log reader as a clean
 * end, and it is exactly the signature the socketpair read timeout produced: the process stopped,
 * said nothing, and the client reported only "server disconnected". So there is no unnamed way out
 * of a run — each path here carries both a code and the sentence that goes on the diagnostic
 * channel.
 *
 * ## Why these are not the lint gate's exit codes
 *
 * A tool call never ends this process. Whether findings breached a gate is a FIELD in a result an
 * agent reads, not a status the operating system carries — reusing the lint command's own exit codes
 * here would make "the deploy should stop" and "the server stopped" the same number, and a wrapper
 * script could not tell them apart.
 *
 * The numbers follow the conventions a shell already knows: 128 + signal for a signaled end, and
 * `EX_SOFTWARE` for a run that broke. The NAMES are the contract; the numbers are what makes the
 * contract legible to something that never read this file.
 */
enum McpExit: string
{
    /** The client closed its end. The ordinary way a session ends. */
    case ClientClosed = 'client_closed';

    /** Interrupted — someone pressed Ctrl-C, or a supervisor sent SIGINT. */
    case Interrupted = 'interrupted';

    /** Asked to stop — SIGTERM, which is how a supervisor retires a server. */
    case Terminated = 'terminated';

    /** The run broke. Not an ending anybody asked for. */
    case Failed = 'failed';

    /** What the process reports to whatever started it. */
    public function code(): int
    {
        return match ($this) {
            self::ClientClosed => 0,
            // 128 + signal, the convention every shell already reads: 130 for SIGINT, 143 for
            // SIGTERM. A wrapper that never heard of SQLens still gets the right idea.
            self::Interrupted => 130,
            self::Terminated => 143,
            // EX_SOFTWARE. Deliberately not 1: a 1 from a server is indistinguishable from the lint
            // gate's "findings breached", and those are answers to different questions.
            self::Failed => 70,
        };
    }

    /**
     * The line that goes on the diagnostic channel, in English.
     *
     * Machine-facing surface, like the tool names: an operator reads it in a log next to their
     * agent's own output, and a supervisor may match on it. Never empty — an ending without a
     * sentence is the silent exit this enum exists to prevent.
     */
    public function reason(): string
    {
        return match ($this) {
            self::ClientClosed => 'the client closed the connection; the server is done',
            self::Interrupted => 'interrupted (SIGINT); the server stopped after the frame it was writing',
            self::Terminated => 'asked to stop (SIGTERM); the server stopped after the frame it was writing',
            self::Failed => 'the server stopped because the run broke; the reason is above this line',
        };
    }
}
