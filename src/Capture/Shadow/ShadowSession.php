<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\Shadow;

use DateTimeImmutable;
use DateTimeZone;

/**
 * A live shadow database a provisioner created and a teardown must remove.
 *
 * It is the one handle that ties provisioning to teardown: the provisioner
 * returns it, the captor runs against it, and the teardown drops exactly the
 * database it names — never a guessed one. Carrying the source connection makes
 * the clone traceable, and the start time lets the session-defense layer bound
 * how long a shadow run may hold resources on the source instance.
 *
 * It holds no PDO and opens nothing. It is a value object describing a database
 * that exists; acting on it (dropping it, connecting to it) is the provisioner's
 * and the captor's job, kept out of the value so a session can be reasoned about
 * and asserted on without a live server.
 */
final readonly class ShadowSession
{
    public function __construct(
        public string $shadowDatabase,
        public string $connectionName,
        public string $sourceConnection,
        public DateTimeImmutable $startedAt,
        /**
         * The throwaway TEMPLATE this run also created, when the engine needed one.
         *
         * PostgreSQL clones from a template, so a shadow run creates two databases and
         * must remove both — a template left behind is the same leak as a clone left
         * behind. Null on an engine that needs no template (MySQL replays a dump
         * straight into the clone), which is a real absence, not an unset field.
         */
        public ?string $templateDatabase = null,
    ) {}

    /**
     * A deterministic array projection. The start time is rendered in UTC ISO-8601
     * so a session logged on two machines reads the same instant, not two local
     * clocks.
     *
     * @return array{shadow_database: string, connection: string, source_connection: string, started_at: string}
     */
    public function toArray(): array
    {
        return [
            'shadow_database' => $this->shadowDatabase,
            'connection' => $this->connectionName,
            'source_connection' => $this->sourceConnection,
            // Rendered in UTC so a session read on two machines shows the same
            // instant, not two local clocks — the same determinism rule the rest of
            // the output follows.
            'started_at' => $this->startedAt->setTimezone(new DateTimeZone('UTC'))->format(DateTimeImmutable::ATOM),
        ];
    }
}
