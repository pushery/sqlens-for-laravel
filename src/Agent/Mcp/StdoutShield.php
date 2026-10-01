<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

use Illuminate\Contracts\Config\Repository;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Symfony\Component\VarDumper\VarDumper;

/**
 * Keeps `stdout` for the protocol and nothing else.
 *
 * ## Why shielding rather than trusting
 *
 * The host application is not ours. Its service providers boot inside this process, its
 * dependencies boot with them, and any one of them may `echo`, `print_r`, or leave a debug
 * dump behind. PHP itself will happily write a deprecation notice to standard output. Any one of
 * those lines lands in the middle of the frame stream, and the client's JSON parser meets a message that
 * never finishes — every later frame is then read against a position that means nothing. What the
 * user sees is "the server is broken", not "something printed a sentence".
 *
 * So the channel is separated here rather than requested politely in documentation.
 *
 * ## Why the frames are not affected
 *
 * Measured: an output buffer captures the PHP output layer — `echo`, `print`, `printf` — and does
 * NOT capture `fwrite()` to the stdout stream resource. The transport writes frames with `fwrite`,
 * so they pass straight through while foreign output is intercepted. That is what makes a blanket
 * buffer safe here rather than a way to swallow the protocol.
 *
 * ## The two lanes that write like the frames do
 *
 * The same property lets two ordinary kinds of foreign output past the buffer. Laravel's CLI
 * dumper, which a forgotten `dump` reaches, writes through a console output built on `STDOUT`,
 * and a log channel on `php://stdout` opens that stream itself; both use `fwrite`. So the shield
 * takes the dump handler while it is up and sends dumps to the diagnostic channel, and
 * {@see self::divertLogStreams()} points such log channels at `php://stderr`. What stays out of
 * reach is code that writes to `STDOUT` itself, and a log handler built around a stream it was
 * handed rather than one it opens from the configuration.
 *
 * ## Why captured output is REPORTED, not dropped
 *
 * A stray line is evidence of a real defect in the host application. Discarding it silently would
 * trade a visible failure for an invisible one: the frame stream would be clean and the bug would
 * live forever. It goes to the diagnostic channel, named, so somebody can find the `echo`.
 *
 * ## THE ONE THING IT CANNOT COVER: output that precedes it
 *
 * `engage()` is called as early as a service provider can manage, and again where the conversation
 * starts. Neither is early enough for a COMPILE-TIME message. PHP emits those when a file is
 * LOADED, which happens in the autoloader — before any provider boots, and therefore before this
 * class exists.
 *
 * Measured: on the dependency floor the package declares, an older `amphp/dns` wrote
 * `Deprecated: Amp\Dns\dnsResolver(): Implicitly marking parameter $dnsConfigLoader as nullable`
 * to standard output, and two end-to-end arms failed with `a line on STDOUT is not a protocol
 * frame`. The shield was not at fault and could not have been: it had not been reached yet.
 *
 * It does not reproduce on the resolved versions — `amphp/dns` v2.4.1 spells the parameter
 * `?DnsResolver $dnsResolver = null`, and loading it under PHP 8.4+ emits nothing. So the exposure
 * is a floor-only one, and the lever for it is a dependency constraint rather than anything here.
 *
 * The limit is written down because the alternative is a reader concluding the shield is broken
 * when a frame stream is corrupted before it engages. It is not: nothing inside this process can
 * intercept a message emitted while the process is still being assembled.
 */
final class StdoutShield
{
    /** The prefix a diverted line carries, so it is obvious it did not come from the protocol. */
    public const string CAPTURE_PREFIX = '[sqlens:mcp] captured output that did not come from the protocol: ';

    private bool $engaged = false;

    private ?string $previousDisplayErrors = null;

    /** Whether the dump handler is this shield's, and so has to be handed back. */
    private bool $holdsDumps = false;

    /** @var callable|null the dump handler this shield replaced */
    private $previousDumpHandler;

    /**
     * The log streams this shield re-pointed, by configuration key, with what they said before.
     *
     * @var array<string, string>
     */
    private array $divertedLogStreams = [];

    private ?Repository $divertedIn = null;

    /** @var resource */
    private $diagnostics;

    /** @param resource|null $diagnostics where diverted output and PHP messages go; STDERR by default */
    public function __construct(mixed $diagnostics = null)
    {
        $this->diagnostics = is_resource($diagnostics) ? $diagnostics : STDERR;
    }

    /**
     * Take the channel, once.
     *
     * Idempotent because it is called from two places on purpose: as early as the service provider
     * can manage, so foreign BOOT output is caught, and again where the conversation starts, so the
     * shield is up even if the early call never happened.
     */
    public function engage(): void
    {
        if ($this->engaged) {
            return;
        }

        $this->engaged = true;

        // PHP's own messages, first. `display_errors = stderr` is the CLI setting that keeps a
        // deprecation notice out of the frame stream even before any handler of ours runs.
        $current = ini_get('display_errors');
        $this->previousDisplayErrors = $current === false ? null : $current;
        ini_set('display_errors', 'stderr');

        set_error_handler(function (int $severity, string $message, string $file, int $line): bool {
            $this->write(sprintf('[sqlens:mcp] PHP message (%d): %s in %s:%d', $severity, $message, $file, $line));

            // Handled. Returning false would hand it back to PHP's own printer, which is the
            // thing being kept away from this process's standard output.
            return true;
        });

        // A dump, next. The handler Laravel registers in the console writes with `fwrite` to
        // `STDOUT`, past the buffer below, so a forgotten `dump` would land in the frame stream.
        // Only where the dumper is installed at all: without it there is no `dump` to forget.
        if (class_exists(VarDumper::class)) {
            $this->previousDumpHandler = VarDumper::setHandler($this->divertDump(...));
            $this->holdsDumps = true;
        }

        // Chunk size 1 so a stray line is diverted when it is written rather than at the end of a
        // session that may last an afternoon.
        ob_start(function (string $chunk): string {
            if (trim($chunk) !== '') {
                $this->write(self::CAPTURE_PREFIX.rtrim($chunk, "\n"));
            }

            // Nothing reaches standard output. The frame stream is written with `fwrite` and never
            // passes through here.
            return '';
        }, 1);
    }

    /**
     * Point every log channel that writes to standard output at standard error.
     *
     * A log handler opens its stream itself and writes it with `fwrite`, the lane the frames use,
     * so the buffer never sees the line: a channel on `php://stdout` put a log line into the frame
     * stream on every call that logged. Each such stream, as `path` or as the `stream` a monolog
     * channel is built with, now names `php://stderr`, and a channel the logger already opened is
     * dropped so that it opens again on the new stream.
     *
     * Called where the shield goes up and again where the conversation starts, so a channel the
     * host configures in between is caught too. Re-pointing a stream twice is a no-op.
     *
     * @param  object|null  $log  the application's log manager, to drop channels it already opened
     */
    public function divertLogStreams(Repository $config, ?object $log = null): void
    {
        $channels = $config->get('logging.channels');

        if (! is_array($channels)) {
            return;
        }

        foreach ($channels as $name => $channel) {
            if (! is_string($name) || ! is_array($channel)) {
                continue;
            }

            $diverted = false;

            foreach (['path', 'with.stream', 'handler_with.stream'] as $key) {
                $stream = data_get($channel, $key);

                if (is_string($stream) && strtolower($stream) === 'php://stdout') {
                    $this->divertedLogStreams['logging.channels.'.$name.'.'.$key] ??= $stream;
                    $config->set('logging.channels.'.$name.'.'.$key, 'php://stderr');
                    $diverted = true;
                }
            }

            if ($diverted) {
                $this->divertedIn = $config;
                $this->write(sprintf('[sqlens:mcp] log channel "%s" wrote to standard output, which carries the protocol; it writes to standard error while the server runs', $name));

                if ($log !== null && method_exists($log, 'forgetChannel')) {
                    $log->forgetChannel($name);
                }
            }
        }
    }

    /**
     * Say a fatal happened, on the diagnostic channel.
     *
     * Takes the error rather than reading it, because a shutdown function cannot be driven from a
     * test that is still running — and a branch nothing executes is a branch nobody has checked.
     * The shape is `error_get_last()`'s own.
     *
     * @param  array{type: int, message: string, file: string, line: int}|null  $last
     */
    public function reportFatal(?array $last): void
    {
        if ($last === null || ! in_array($last['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            // An ordinary end, or a message the error handler already answered. Saying something
            // here would put a line on the channel for every clean exit.
            return;
        }

        $this->write(sprintf('[sqlens:mcp] fatal: %s in %s:%d', $last['message'], $last['file'], $last['line']));
    }

    /**
     * Take the channel if this process is the MCP server.
     *
     * The decision lives here rather than in the service provider so it is a branch with a test
     * either side of it, instead of a condition in a boot method that nothing can exercise.
     *
     * @param  list<string>  $argv
     */
    public function engageIfWanted(array $argv): void
    {
        if (in_array('sqlens:mcp', $argv, true)) {
            $this->engage();
        }
    }

    /** Give the channel back — for a test, and for anything that outlives one conversation. */
    public function release(): void
    {
        if (! $this->engaged) {
            return;
        }

        $this->engaged = false;

        ob_end_clean();
        restore_error_handler();

        if ($this->holdsDumps) {
            VarDumper::setHandler($this->previousDumpHandler);
            $this->holdsDumps = false;
            $this->previousDumpHandler = null;
        }

        foreach ($this->divertedLogStreams as $key => $stream) {
            $this->divertedIn?->set($key, $stream);
        }

        $this->divertedLogStreams = [];
        $this->divertedIn = null;

        if ($this->previousDisplayErrors !== null) {
            ini_set('display_errors', $this->previousDisplayErrors);
        }
    }

    /** Whether the channel is currently held. */
    public function isEngaged(): bool
    {
        return $this->engaged;
    }

    /** A dump, rendered without colors and reported like any other foreign output. */
    private function divertDump(mixed $value, ?string $label = null): void
    {
        $dumper = new CliDumper;
        $dumper->setColors(false);

        $rendered = (string) $dumper->dump(new VarCloner()->cloneVar($value), true);

        $this->write(self::CAPTURE_PREFIX.($label !== null && $label !== '' ? $label.' ' : '').rtrim($rendered, "\n"));
    }

    private function write(string $line): void
    {
        fwrite($this->diagnostics, $line.PHP_EOL);
    }
}
