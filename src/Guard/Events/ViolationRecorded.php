<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Events;

/**
 * A guardrail finding, dispatched beside the log line it writes, for a listener that hands findings
 * on, such as an APM client that reports them per request.
 *
 * It carries what the log line carries and nothing more: the statement with every literal reduced
 * to its shape, and the bindings, where the profile includes them at all, reduced to their type and
 * length. The raw statement and the raw bindings never reach a listener, for the reason they never
 * reach a log: a binding can be a password or somebody's address, and a listener is code that sends
 * things elsewhere.
 */
final readonly class ViolationRecorded
{
    /**
     * @param  string  $profile  the guard profile that recorded it
     * @param  string  $type  the kind of finding, such as `lazy_loading` or `slow_query`
     * @param  string  $level  the PSR-3 level the log line went out at
     * @param  string  $message  the sentence of the log line, without its prefix
     * @param  ?string  $sql  the statement as the log line has it, its literals masked, or null
     * @param  array<string, mixed>  $context  the context of the log line, count, time and location included where the finding has them
     */
    public function __construct(
        public string $profile,
        public string $type,
        public string $level,
        public string $message,
        public ?string $sql,
        public array $context,
    ) {}
}
