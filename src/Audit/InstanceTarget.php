<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Catalog\InstanceIdentity;
use Pushery\SQLens\Catalog\PoolerReading;

/**
 * Which instance an audit is about — the configured intent and, once read, the observed reality.
 *
 * Both halves, deliberately. A report that carried only the configuration would be describing a
 * server it may never have reached; one that carried only the observation could not say whether it
 * reached the server the operator meant. The gap between them is a finding, and a finding needs
 * both sides to state.
 *
 * The gap is not hypothetical. Laravel resolves a read/write split with two independent random
 * choices, and a `host` array is shuffled — so a project can configure one thing and be audited on
 * another, run after run, with nothing in the framework's public surface to say which.
 */
final readonly class InstanceTarget
{
    private function __construct(
        public string $connection,
        public string $driver,
        /** What the configuration says this connection points at — an intent, not an observation. */
        public ?string $configuredHost,
        public ?int $configuredPort,
        public ?string $configuredDatabase,
        /** What the server said about itself, or null before anything connected. */
        public ?InstanceIdentity $identity = null,
        /**
         * The read host this run is pinned to, when the configuration offered a choice.
         *
         * Null when there was nothing to choose — a single host, a socket, a DSN. It is NOT a
         * default: a null here means the question never arose, not that one was picked.
         */
        public ?string $pinnedHost = null,
        /** How the reading reached the server — established outside the catalog session. */
        public ?PoolerReading $pooler = null,
    ) {}

    public static function of(
        string $connection,
        string $driver,
        ?string $configuredHost = null,
        ?int $configuredPort = null,
        ?string $configuredDatabase = null,
        ?string $pinnedHost = null,
    ): self {
        return new self($connection, $driver, $configuredHost, $configuredPort, $configuredDatabase, null, $pinnedHost);
    }

    /** The same target, now carrying what the server said about itself. */
    public function withIdentity(InstanceIdentity $identity): self
    {
        return new self(
            $this->connection,
            $this->driver,
            $this->configuredHost,
            $this->configuredPort,
            $this->configuredDatabase,
            $identity,
            $this->pinnedHost,
            $this->pooler,
        );
    }

    /** The same target, now knowing how the reading reached the server. */
    public function withPooler(PoolerReading $pooler): self
    {
        return new self(
            $this->connection,
            $this->driver,
            $this->configuredHost,
            $this->configuredPort,
            $this->configuredDatabase,
            $this->identity,
            $this->pinnedHost,
            $pooler,
        );
    }

    /**
     * Where the configuration and the server disagree — field name => [configured, observed].
     *
     * Empty before anything connected, and empty when they agree. A field the server could not
     * answer is NOT a divergence: "the reading could not say" and "the reading said something else"
     * are different, and reporting the first as the second would raise an alarm about a local
     * socket.
     *
     * The HOST is deliberately compared only when both sides are present and the driver reports the
     * dialled address rather than its own name. On MySQL `@@hostname` is the server's machine name —
     * measured — so comparing it against a configured `127.0.0.1` would flag every correct setup.
     *
     * @return array<string, array{configured: string, observed: string}>
     */
    public function divergences(): array
    {
        $identity = $this->identity;

        if (! $identity instanceof InstanceIdentity) {
            return [];
        }

        $divergences = [];

        if ($this->configuredPort !== null && $identity->port !== null && $this->configuredPort !== $identity->port) {
            $divergences['port'] = ['configured' => (string) $this->configuredPort, 'observed' => (string) $identity->port];
        }

        if ($this->configuredDatabase !== null && $identity->database !== null && $this->configuredDatabase !== $identity->database) {
            $divergences['database'] = ['configured' => $this->configuredDatabase, 'observed' => $identity->database];
        }

        return $divergences;
    }

    /**
     * Whether the server this run reached is the one it pinned.
     *
     * Asked AFTER connecting, of the server itself — the pin is written onto a config the driver
     * then uses, and "the config says db2" is not the same claim as "db2 answered". A pin that
     * silently did not take effect would produce a report about the wrong database that reads
     * exactly like a right one.
     *
     * The comparison is deliberately narrow: two literal addresses, or two identical strings. A
     * pinned NAME against an observed ADDRESS is {@see PinVerdict::Unverifiable} rather than a
     * divergence, because resolving the name would mean a DNS lookup — a network call, and a second
     * source of truth — inside a run whose whole contract is that the same state gives the same
     * result.
     */
    public function pinVerdict(): PinVerdict
    {
        $pinned = $this->pinnedHost;

        if ($pinned === null) {
            return PinVerdict::NotPinned;
        }

        $observed = $this->identity?->host;

        if ($observed === null) {
            // A local socket, a managed database that withholds it, an identity probe that failed.
            // Each is a reason the check could not run, and none of them is a reason to call it done.
            return PinVerdict::Unverifiable;
        }

        if ($pinned === $observed) {
            return PinVerdict::Confirmed;
        }

        // Only two ADDRESSES can disagree in a way this package is entitled to act on. Anything
        // else — a name against an address, a short name against an FQDN — is a comparison SQLens
        // cannot make, and saying so is the honest answer.
        return $this->isAddress($pinned) && $this->isAddress($observed)
            ? PinVerdict::Divergent
            : PinVerdict::Unverifiable;
    }

    /** Whether a host is a literal IP address rather than a name that would need resolving. */
    private function isAddress(string $host): bool
    {
        return filter_var($host, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * Whether this instance accepts writes, which decides what its answers are worth.
     *
     * Derived rather than stored, for the same reason {@see pinVerdict()} is: the role is a reading
     * OF the identity, and a second field holding it could be set while the identity said otherwise.
     */
    public function role(): InstanceRole
    {
        return InstanceRole::of($this->identity);
    }

    /** A stable one-line rendering for the report header. */
    public function describe(): string
    {
        $identity = $this->identity;

        return $identity instanceof InstanceIdentity
            ? sprintf('%s (%s) → %s', $this->connection, $this->driver, $identity->describe())
            : sprintf('%s (%s)', $this->connection, $this->driver);
    }
}
