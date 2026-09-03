<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * A request to stop, raised from a signal handler and read by the read loop.
 *
 * ## Why a flag and not an exit
 *
 * A signal can arrive at any instruction, including halfway through writing a frame. Exiting from
 * the handler would leave a message that stops mid-token on the wire, and a client parser that
 * meets one never recovers — every later frame is read against a position that means nothing. So
 * the handler only records the reason; the loop notices between frames, when nothing is half
 * written.
 *
 * That is the whole reason this object exists rather than a closure that calls `exit`.
 */
final class ShutdownRequest
{
    private ?McpExit $reason = null;

    /**
     * Ask the loop to stop, and say why.
     *
     * The FIRST reason wins. A supervisor that sends SIGTERM and then SIGINT a moment later has not
     * changed its mind about why it is stopping the server, and reporting the second signal would
     * describe the impatience rather than the decision.
     */
    public function request(McpExit $reason): void
    {
        $this->reason ??= $reason;
    }

    /** Why the loop should stop, or null while nobody has asked. */
    public function reason(): ?McpExit
    {
        return $this->reason;
    }

    public function isRequested(): bool
    {
        return $this->reason instanceof McpExit;
    }
}
