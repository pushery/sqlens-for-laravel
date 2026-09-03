<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

/**
 * Which hosts a connection could actually read from — read off the configuration, never off a
 * connection.
 *
 * ## The failure this exists to prevent
 *
 * Laravel resolves a read/write split by CHOOSING, and it chooses at random: a `host` array is
 * shuffled, and the read side and the write side are picked independently. A project with two read
 * replicas configured therefore gets a different one on different runs, and nothing in the
 * framework's public surface says which one answered.
 *
 * For an application that is fine — any replica will do. For an audit it is not: server settings,
 * replication lag and sometimes the schema itself differ between a primary and its replicas, so a
 * report that does not name its host is a report about an unknown database. Two runs of the same
 * unchanged project could then disagree, and the difference would look like drift.
 *
 * So SQLens does not choose. Either the configuration leaves exactly one possibility, or the
 * operator names one, or the run is refused.
 *
 * ## Why the READ side and not the write side
 *
 * A catalog audit reads. `Connection::getConfig()` describes the WRITE side, which is the trap the
 * spike behind this class found: asking the framework what it is connected to answers a question
 * about a connection the audit is not using. The read block is read from the raw configuration
 * because Laravel exposes no getter for it.
 */
final readonly class ReadTopology
{
    /** @param  list<string>  $hosts */
    private function __construct(public array $hosts, public bool $configuresSplit) {}

    /**
     * The read topology of one connection's configuration.
     *
     * Takes the array shape a config repository actually hands back — keys of any type, values of
     * any type — rather than a narrowed one it cannot guarantee. Three string keys are looked up and
     * everything else is ignored, so a caller that filtered first would be doing ceremony for a
     * promise nobody can keep about `config('database.connections.x')`.
     *
     * @param  array<array-key, mixed>  $settings
     */
    public static function of(array $settings): self
    {
        $read = $settings['read'] ?? null;
        $configuresSplit = is_array($read) || is_array($settings['write'] ?? null);

        return new self(
            is_array($read)
                ? self::hostsInReadBlock($read, $settings)
                : self::hostsIn($settings['host'] ?? null),
            $configuresSplit,
        );
    }

    /**
     * The hosts a `read` block leaves open — in BOTH shapes the framework accepts.
     *
     * `ConnectionFactory::getReadWriteConfig()` branches on `isset($config['read'][0])`:
     *
     * ```php
     * 'read' => ['host' => ['a', 'b']]            // a config fragment, merged over the connection
     * 'read' => [['host' => 'a'], ['host' => 'b']] // a LIST of configs, one picked with Arr::random
     * ```
     *
     * Only the first was understood here, and the second is the one that hurts: a list has no `host`
     * key of its own, so the lookup fell through to the connection's own `host`, reported ONE host
     * and answered `isAmbiguous() === false`. The audit then ran and named the primary while Laravel
     * read from a replica it had picked at random — precisely the non-determinism this class
     * documents itself as preventing, arriving through the shape nobody had checked.
     *
     * An entry in the list that names no host of its own inherits the connection's, because that is
     * what `mergeReadWriteConfig()` does to it.
     *
     * @param  array<array-key, mixed>  $read
     * @param  array<array-key, mixed>  $settings
     * @return list<string>
     */
    private static function hostsInReadBlock(array $read, array $settings): array
    {
        if (! isset($read[0])) {
            // The framework's own precedence: the read block's host wins where there is one,
            // otherwise the connection's. Reproducing it rather than guessing is the point — a
            // topology that disagreed with the framework would refuse runs that are fine and permit
            // ones that are not.
            return self::hostsIn(array_key_exists('host', $read) ? $read['host'] : ($settings['host'] ?? null));
        }

        $hosts = [];

        foreach ($read as $entry) {
            $host = is_array($entry) && array_key_exists('host', $entry)
                ? $entry['host']
                : ($settings['host'] ?? null);

            foreach (self::hostsIn($host) as $candidate) {
                $hosts[] = $candidate;
            }
        }

        return array_values(array_unique($hosts));
    }

    /**
     * Whether the configuration leaves more than one possibility open.
     *
     * Zero hosts is NOT ambiguous. A connection configured through a socket or a DSN names no host
     * at all, and refusing those would break every project that does not use TCP — the question this
     * class asks is "did somebody configure a CHOICE", and no host is not a choice.
     */
    public function isAmbiguous(): bool
    {
        return count($this->hosts) > 1;
    }

    /** Whether this host is one the configuration actually offers. */
    public function offers(string $host): bool
    {
        return in_array($host, $this->hosts, true);
    }

    /**
     * The one host this configuration leaves, or null when it leaves none or several.
     *
     * Null for several rather than the first: taking the first would be choosing, which is the whole
     * thing this class exists not to do — and it would be a choice that looks stable because
     * `hosts` is ordered, right up until somebody reorders the config file.
     */
    public function onlyHost(): ?string
    {
        return count($this->hosts) === 1 ? $this->hosts[0] : null;
    }

    /**
     * A host value as a list, whatever shape it arrived in.
     *
     * @return list<string>
     */
    private static function hostsIn(mixed $host): array
    {
        if (is_string($host)) {
            return $host === '' ? [] : [$host];
        }

        if (! is_array($host)) {
            return [];
        }

        $hosts = [];

        foreach ($host as $candidate) {
            if (is_string($candidate) && $candidate !== '') {
                $hosts[] = $candidate;
            }
        }

        return $hosts;
    }
}
