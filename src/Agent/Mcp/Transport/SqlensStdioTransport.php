<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Transport;

use Closure;
use Illuminate\Support\Sleep;
use Laravel\Mcp\Server\Contracts\Transport;
use Pushery\SQLens\Agent\Mcp\ShutdownRequest;
use Pushery\SQLens\Exceptions\McpFrameNotDelivered;

/**
 * Line-delimited JSON-RPC frames over two streams — the pipe under the MCP server.
 *
 * ## Why not simply the SDK's transport
 *
 * The SDK ships one, and its read loop is exactly right; the loop below is the same pattern
 * deliberately, not a better idea. Two things it cannot give us:
 *
 * 1. **Its streams are the `STDIN`/`STDOUT` constants.** Nothing can be substituted, so the two
 *    behaviors this class exists to guarantee — that a read timeout is not mistaken for a hangup,
 *    and that a short write is completed rather than cut off — have no way to be tested at all. A
 *    guarantee nobody can test is a sentence in a docblock.
 * 2. **It writes with a single `fwrite()`** and does not look at the return value. A short write on
 *    a socket is not an error; it is a normal outcome that returns the number of bytes taken. The
 *    remainder is then simply lost, and what the client receives is a frame that ends mid-token —
 *    which desynchronizes its parser on a message that never finishes.
 *
 * ## The read loop, and the failure it exists to prevent
 *
 * A node-based MCP client hands stdio to a child as a **unix socketpair, not a pipe** — every one
 * of them is built on libuv, which does that by default. On a socket-backed stream PHP applies
 * `default_socket_timeout` (60 s by default) to `php://stdin` as well, so a blocking `fgets()`
 * returns `false` after a minute **without EOF**. The obvious loop, `while (fgets($in) !== false)`,
 * then ends "cleanly": exit 0, nothing on stderr, and the client reports only "server
 * disconnected". Every pause longer than a minute — a long tool call, a person thinking — triggers
 * it. Measured, not theorized: a socketpair instance died at 60.2 s while a FIFO instance lived
 * past 360 s.
 *
 * So the loop is non-blocking, and **only real EOF ends it**. `false` means "nothing to read yet"
 * and is answered with a short sleep, which is the difference between a server that survives a
 * lunch break and one that does not.
 *
 * ## What it deliberately does not do
 *
 * It touches no database, holds no state beyond the handler, and knows nothing about what a frame
 * means. Shielding stdout from foreign output and the shutdown/signal behavior are separate
 * pieces of work; this one reads frames and writes frames.
 */
final class SqlensStdioTransport implements Transport
{
    /** How long to wait before looking again when the stream had nothing. */
    public const int IDLE_SLEEP_MICROSECONDS = 10_000;

    /** How long the output may take no byte at all before a frame is given up as undeliverable. */
    public const int WRITE_STALL_MICROSECONDS = 30_000_000;

    private ?Closure $handler = null;

    /**
     * @param  resource  $input
     * @param  resource  $output
     */
    public function __construct(
        // `mixed` natively, `resource` in the docblock above. PHP has no `resource` type
        // declaration, and an undeclared parameter is a hole in the type-coverage floor — so the
        // native type says "anything" and the docblock says what it actually is, which is the only
        // combination that satisfies both the analyzer and the gate.
        private readonly mixed $input,
        private readonly mixed $output,
        private readonly ?ShutdownRequest $shutdown = null,
    ) {}

    public function onReceive(Closure $handler): void
    {
        $this->handler = $handler;
    }

    /**
     * Put one frame on the wire, whole.
     *
     * `fwrite()` on a socket may take fewer bytes than it was given and report exactly that; it is
     * not an error and it is not rare under load. Writing once and walking away leaves the client
     * with a frame that stops mid-token, and a JSON parser that meets one has no way back — every
     * later frame is read against a broken position.
     *
     * So the remainder is pushed until it is gone, and a stream that takes nothing for a moment is
     * waited for. A non-blocking stream answers a full buffer with zero bytes, and a terminal makes
     * stdout non-blocking as soon as {@see run()} makes stdin so, because the two share one open
     * file description there. Zero means "not yet", as a blocking write would have waited.
     *
     * A stream that fails outright, or takes no byte for {@see self::WRITE_STALL_MICROSECONDS}, is a
     * NAMED failure rather than a silent truncation. The part already written stays on the wire, and
     * the exception says how much of the frame that was.
     *
     * @throws McpFrameNotDelivered
     */
    public function send(string $message): void
    {
        $frame = $message.PHP_EOL;
        $total = strlen($frame);
        $written = 0;
        $stalled = 0;

        while ($written < $total) {
            $chunk = fwrite($this->output, substr($frame, $written));

            if ($chunk === false) {
                throw McpFrameNotDelivered::afterBytes($written, $total);
            }

            if ($chunk === 0) {
                if ($stalled >= self::WRITE_STALL_MICROSECONDS) {
                    throw McpFrameNotDelivered::afterBytes($written, $total);
                }

                Sleep::usleep(self::IDLE_SLEEP_MICROSECONDS);
                $stalled += self::IDLE_SLEEP_MICROSECONDS;

                continue;
            }

            $written += $chunk;
            $stalled = 0;
        }
    }

    /**
     * Read frames until the client really goes away.
     *
     * Non-blocking, and `feof()` is the ONLY thing that ends it — see the class docblock for the
     * minute-long silence this shape exists to survive.
     */
    public function run(): void
    {
        // In a terminal stdin and stdout are one open file description, so this makes stdout
        // non-blocking as well. send() waits out a stream that takes nothing for a moment, which is
        // what keeps a long frame whole there.
        stream_set_blocking($this->input, false);

        // The shutdown flag is read HERE, between frames, and nowhere else. A signal can arrive at
        // any instruction — including halfway through a write — so a handler that exited would
        // leave a message that stops mid-token on the wire. Noticing between frames is what makes
        // "no half frames" a property of the shape rather than a hope.
        while (! feof($this->input) && ! ($this->shutdown?->isRequested() ?? false)) {
            $line = fgets($this->input);

            if ($line === false) {
                // Nothing to read YET. On a socket this is also what a read timeout looks like,
                // and treating it as a hangup is the whole defect: the server would exit silently
                // while the client was still there.
                Sleep::usleep(self::IDLE_SLEEP_MICROSECONDS);

                continue;
            }

            if (trim($line) === '') {
                continue;
            }

            if ($this->handler instanceof Closure) {
                ($this->handler)($line);
            }
        }
    }

    public function stream(Closure $stream): void
    {
        $stream();
    }
}
