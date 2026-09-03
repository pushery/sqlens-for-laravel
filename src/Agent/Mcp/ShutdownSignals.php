<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * Turns `SIGTERM` and `SIGINT` into a request the read loop can act on between frames.
 *
 * ## Why `ext-pcntl` being absent is REPORTED
 *
 * It is not guaranteed on a target system — plenty of PHP builds ship without it, and a container
 * image is as likely to lack it as to have it. A server that quietly ran without signal handling
 * would look identical to one that had it, right up to the moment a supervisor sent SIGTERM and the
 * process died mid-frame instead of finishing cleanly.
 *
 * So the absence is stated ONCE, by name, on the diagnostic channel: the operator learns that this
 * installation stops abruptly rather than politely, and can decide whether that matters. Everything
 * else keeps working — the EOF path, which is how a session normally ends, needs no signals at all.
 *
 * ## Why async signals rather than ticks
 *
 * `declare(ticks=1)` costs a check on every statement of every file that declares it, and it does
 * not reach code compiled elsewhere. `pcntl_async_signals(true)` delivers between opcodes without
 * either problem.
 */
final readonly class ShutdownSignals
{
    /** The line an operator sees when this build cannot listen for signals. */
    public const string UNAVAILABLE_NOTICE = '[sqlens:mcp] ext-pcntl is not installed, so SIGTERM and SIGINT cannot be handled: this server will stop abruptly rather than after the frame it is writing. The ordinary end of a session — the client closing its side — is unaffected.';

    /**
     * Listen, if this build can.
     *
     * @param  resource  $diagnostics
     * @param  bool|null  $available  whether this build can listen at all; null asks the runtime.
     *                                It is a parameter rather than a fact because the branch that
     *                                matters most — the one where the extension is MISSING — is
     *                                unreachable on a machine that has it, and a guarantee nobody
     *                                can exercise is a sentence in a docblock.
     * @return bool whether signal handling is actually in place
     */
    public static function install(ShutdownRequest $request, mixed $diagnostics, ?bool $available = null): bool
    {
        if (! ($available ?? self::isAvailable())) {
            fwrite($diagnostics, self::UNAVAILABLE_NOTICE.PHP_EOL);

            return false;
        }

        pcntl_async_signals(true);

        pcntl_signal(SIGTERM, static function () use ($request): void {
            $request->request(McpExit::Terminated);
        });

        pcntl_signal(SIGINT, static function () use ($request): void {
            $request->request(McpExit::Interrupted);
        });

        return true;
    }

    /**
     * Whether this build can handle signals at all.
     *
     * Asked as a question rather than assumed, so the test for the missing-extension path is a test
     * of this class rather than of a machine that happens to lack it.
     */
    public static function isAvailable(): bool
    {
        return function_exists('pcntl_async_signals') && function_exists('pcntl_signal');
    }
}
