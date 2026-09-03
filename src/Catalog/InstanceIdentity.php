<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Which instance a reading was actually made against — asked of the SERVER, never of the config.
 *
 * The distinction is not pedantry. Laravel resolves a read/write split with two independent random
 * choices (`Arr::random` over a list of read configs, `Arr::shuffle` over a `host` array), and the
 * merged config it then exposes describes the WRITE side: a `SELECT` can run on one machine while
 * `getConfig('host')` names another, and the framework offers no public getter for the read config
 * it resolved. Measured against the framework, not inferred from its documentation.
 *
 * So a report that quoted the configuration would be describing a server it may not have read.
 *
 * ## Every field is three-valued, and that is the whole design
 *
 * A field is either a value the server gave, or a named reason it could not. Never a guess and
 * never a blank: an audit that reported no host would be indistinguishable from one that reported
 * the wrong one, and both read as "fine" to somebody scanning the header. `inet_server_addr()`
 * returns NULL over a Unix socket — an ordinary local setup, not a fault — and a managed database
 * may withhold the rest, so the absent cases are the common ones rather than the exotic ones.
 */
final readonly class InstanceIdentity
{
    /**
     * @param  array<string, UndeterminedReason>  $unavailable  field name => why the server did not answer it
     */
    private function __construct(
        public string $connection,
        public ?string $host,
        public ?int $port,
        public ?string $database,
        public ?string $serverVersion,
        /**
         * Whether the instance refuses writes — a replica, or a primary somebody has sealed.
         *
         * A ROLE INDICATION, deliberately not a replication verdict: PostgreSQL's
         * `pg_is_in_recovery()` and MySQL's `read_only` both answer "does this instance accept
         * writes", which is what changes an audit's meaning. Whether replication is healthy, how
         * far behind it is and who the primary is are different questions on different views, and
         * they belong to the deploy suite rather than here.
         */
        public ?bool $readOnly,
        public array $unavailable,
    ) {}

    /**
     * @param  array<string, UndeterminedReason>  $unavailable
     */
    public static function of(
        string $connection,
        ?string $host = null,
        ?int $port = null,
        ?string $database = null,
        ?string $serverVersion = null,
        ?bool $readOnly = null,
        array $unavailable = [],
    ): self {
        return new self($connection, $host, $port, $database, $serverVersion, $readOnly, $unavailable);
    }

    /**
     * The whole identity as one undetermined reading — the server answered nothing at all.
     *
     * A single named reason for every field, rather than five copies of it: a reader who cannot
     * reach the instance learns that once, and a report listing the same sentence five times buries
     * the one fact it carries.
     */
    public static function unavailable(string $connection, UndeterminedReason $reason): self
    {
        return new self($connection, null, null, null, null, null, array_fill_keys(
            ['host', 'port', 'database', 'server_version', 'read_only'],
            $reason,
        ));
    }

    /** Why a field is missing, or null when it is not missing. */
    public function reasonFor(string $field): ?UndeterminedReason
    {
        return $this->unavailable[$field] ?? null;
    }

    /**
     * Whether every field was answered.
     *
     * Used to decide whether a report may state the instance plainly or has to qualify it. It is
     * NOT a health check: a local socket connection is complete-minus-host and perfectly fine.
     */
    public function isComplete(): bool
    {
        return $this->unavailable === [];
    }

    /**
     * A stable, human-readable rendering — `host:port/database`, with each missing part named.
     *
     * Deterministic by construction: same instance, same string, in a report two runs can diff.
     */
    public function describe(): string
    {
        return sprintf(
            '%s:%s/%s',
            $this->host ?? $this->missing('host'),
            $this->port === null ? $this->missing('port') : (string) $this->port,
            $this->database ?? $this->missing('database'),
        );
    }

    /**
     * How a missing field renders: `(host: missing_privilege)`.
     *
     * The REASON is in the rendering, not just the absence. "(host)" would tell a reader that
     * something is missing and leave them to guess whether it is a local socket, a withheld
     * privilege or a pooler — three situations with three different responses.
     */
    private function missing(string $field): string
    {
        $reason = $this->reasonFor($field);

        return '('.$field.': '.($reason instanceof UndeterminedReason ? $reason->value : 'unknown').')';
    }
}
