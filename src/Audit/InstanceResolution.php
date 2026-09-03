<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Drivers\DriverResolutionFailure;

/**
 * The answer to "which instance should this audit address" — a target, or a named refusal.
 *
 * Two shapes rather than an exception, because both are ordinary outcomes a command has to report
 * differently: an ambiguous configuration is a misconfiguration the operator fixes, and an
 * unsupported engine is a message about scope. Neither is exceptional, and throwing for either
 * would make the command catch its way through normal operation.
 */
final readonly class InstanceResolution
{
    /**
     * @param  list<string>  $candidates  the supported connections that made the choice ambiguous
     */
    private function __construct(
        public ?InstanceTarget $target,
        public ?DriverResolutionFailure $unsupported,
        public bool $ambiguous,
        public array $candidates,
        /**
         * The read hosts that made a run ambiguous, or the one that was pinned and is not offered.
         *
         * Kept apart from `$candidates` — which names CONNECTIONS — because the two refusals need
         * different sentences and different fixes: one is answered with `--connection`, the other
         * with `--host`, and a consumer that could not tell them apart would print the wrong one.
         *
         * @var list<string>
         */
        public array $hosts = [],
        public bool $ambiguousHosts = false,
        public ?string $unofferedHost = null,
    ) {}

    public static function resolved(InstanceTarget $target): self
    {
        return new self($target, null, false, []);
    }

    public static function unsupported(DriverResolutionFailure $failure): self
    {
        return new self(null, $failure, false, []);
    }

    /**
     * More than one supported connection and nothing said which — a refusal, on purpose.
     *
     * Laravel's default connection is NOT taken as an answer here. It is a sensible default for an
     * application's own queries and a terrible one for an audit: which instance was read is part of
     * what the report ASSERTS, and a replica carries different settings, a different lag and
     * sometimes a different schema. Picking one silently would put a claim in the report that
     * nobody made.
     *
     * @param  list<string>  $candidates
     */
    public static function ambiguous(array $candidates): self
    {
        sort($candidates);

        return new self(null, null, true, $candidates);
    }

    /**
     * More than one read host and nothing said which — refused, for the same reason as an ambiguous
     * connection and with a sharper edge.
     *
     * Laravel SHUFFLES a host array and picks the read and write sides independently, so this is not
     * a theoretical ambiguity: two runs of an unchanged project genuinely reach different servers,
     * and the difference between a primary and its replica shows up as drift in a report that never
     * said which one it was about.
     *
     * @param  list<string>  $hosts
     */
    public static function ambiguousReadHosts(array $hosts): self
    {
        sort($hosts, SORT_STRING);

        return new self(null, null, false, [], $hosts, true);
    }

    /**
     * A host was pinned that the configuration does not offer — a typo, refused rather than obeyed.
     *
     * Connecting to it anyway would audit a server the project never configured, and reporting that
     * as the project's database is worse than not running at all.
     *
     * @param  list<string>  $offered
     */
    public static function unofferedHost(string $pinned, array $offered): self
    {
        sort($offered, SORT_STRING);

        return new self(null, null, false, [], $offered, false, $pinned);
    }

    public function isResolved(): bool
    {
        return $this->target instanceof InstanceTarget;
    }
}
