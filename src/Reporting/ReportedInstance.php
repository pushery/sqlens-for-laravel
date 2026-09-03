<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

/**
 * Which instance a report is about, in the form a report can print.
 *
 * ## Why the reporting layer has its own shape for this
 *
 * The audit suite already has a richer object for the same subject — it carries the configured
 * intent, the observed identity, the pooler reading and the logic that compares them. Putting THAT
 * into the run header would make the reporting layer, which the lint suite also uses, depend on
 * the audit suite. The header would then be unavailable to the suite that has no instance to
 * report, and a layer that exists to render would start knowing how instances are resolved.
 *
 * So the audit projects onto this, exactly as it projects a resolved version onto
 * {@see ReportedServerVersion}: a flat, already-decided, driver-neutral record with no logic of
 * its own. Every field here is a conclusion somebody else reached.
 *
 * ## Every field can be absent, and absence is not blank
 *
 * A local socket gives no host. A managed database withholds the role. A run that never addressed
 * an instance has none of it. Each of those is an ordinary situation rather than a fault, and the
 * header prints "unknown" rather than an empty space — because a blank field and a field nobody
 * asked are indistinguishable to somebody scanning a report, and only one of them is fine.
 */
final readonly class ReportedInstance
{
    public function __construct(
        public string $connection,
        public string $driver,
        /** The host the SERVER named, or the pinned one when it could not — never the config's guess. */
        public ?string $host,
        public ?int $port,
        public ?string $database,
        /** `primary`, `replica` or `undetermined` — already decided by the audit's role reading. */
        public string $role,
        /** Why the role is undetermined, when it is. Null on a decided role. */
        public ?string $roleReason,
        /** Whether a pinned host was confirmed by the server, contradicted, or could not be checked. */
        public ?string $pinVerdict = null,
        /** Whether the reading reached the server through a transaction pooler. */
        public ?string $poolerVerdict = null,
    ) {}

    /**
     * Fixed-key-order array form for the JSON reporter.
     *
     * @return array{
     *     connection: string,
     *     driver: string,
     *     host: string|null,
     *     port: int|null,
     *     database: string|null,
     *     role: string,
     *     role_reason: string|null,
     *     pin_verdict: string|null,
     *     pooler: string|null,
     * }
     */
    public function toArray(): array
    {
        return [
            'connection' => $this->connection,
            'driver' => $this->driver,
            'host' => $this->host,
            'port' => $this->port,
            'database' => $this->database,
            'role' => $this->role,
            'role_reason' => $this->roleReason,
            'pin_verdict' => $this->pinVerdict,
            'pooler' => $this->poolerVerdict,
        ];
    }

    /**
     * One line for the console header.
     *
     * The role is always printed, including when it is undetermined and why. A report that
     * silently omitted an unknown role would read like one taken on the primary, which is the
     * reading that makes a replica's settings look like a production problem.
     */
    public function describe(): string
    {
        $where = $this->host ?? 'unknown host';

        if ($this->port !== null) {
            $where .= ':'.$this->port;
        }

        return sprintf(
            '%s (%s) %s/%s role=%s%s',
            $this->connection,
            $this->driver,
            $where,
            $this->database ?? 'unknown database',
            $this->role,
            $this->roleReason === null ? '' : ' ('.$this->roleReason.')',
        );
    }
}
