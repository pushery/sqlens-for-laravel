<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Illuminate\Support\Arr;
use Pushery\SQLens\Drivers\EffectiveConnectionConfig;

/**
 * The server a connection's migrations reach, read off its configuration: the write side of a
 * read/write split, and the connection itself otherwise.
 *
 * The deploy commands judge that server. A preflight reads the locks and the activity a migration
 * will wait on, drift compares the schema the migrations built, and the verification after a deploy
 * reads what they left behind, and all three happen where `migrate` runs. A replica answers none of
 * those questions: its locks are not the ones a migration waits on, and its schema can lag.
 *
 * The write side is resolved the way Laravel's connection factory resolves it: a `write` block laid
 * over the connection, or one entry of a list of them, and a `host` that may be a list the framework
 * shuffles. Where that leaves more than one server, nothing here chooses. A pinned host the write side
 * offers settles it, and otherwise there is no answer.
 */
final readonly class PrimaryEndpoint
{
    /**
     * @param  array<array-key, mixed>|null  $settings  the one server's configuration, or null when the write side leaves several
     * @param  list<string>  $hosts  every host the write side offers
     */
    private function __construct(public ?array $settings, public array $hosts) {}

    /**
     * @param  array<array-key, mixed>  $config  the connection as `database.connections` holds it
     * @param  string|null  $pinnedHost  a host that settles the choice when the write side offers it
     */
    public static function of(array $config, ?string $pinnedHost): self
    {
        $candidates = [];

        foreach (self::writeSides(EffectiveConnectionConfig::withoutUrl($config)) as $side) {
            $hosts = self::hostsIn($side['host'] ?? null);

            // A side that names no host reaches its server through a socket or a DSN: one server and
            // no choice, for the framework as much as here.
            foreach ($hosts === [] ? [null] : $hosts as $host) {
                $candidates[] = ['side' => $side, 'host' => $host];
            }
        }

        $offered = array_values(array_unique(array_filter(array_column($candidates, 'host'), is_string(...))));
        $pinned = array_values(array_filter($candidates, static fn (array $candidate): bool => $pinnedHost !== null && $candidate['host'] === $pinnedHost));

        $chosen = match (true) {
            count($pinned) === 1 => $pinned[0],
            count($candidates) === 1 => $candidates[0],
            default => null,
        };

        if ($chosen === null) {
            return new self(null, $offered);
        }

        $settings = $chosen['side'];

        if ($chosen['host'] !== null) {
            $settings['host'] = $chosen['host'];
        }

        return new self($settings, $offered);
    }

    /**
     * Each configuration the framework could open the write connection with.
     *
     * `ConnectionFactory::make()` opens a split only when a `read` block is set; without one it
     * connects with the connection's own keys and ignores a `write` block altogether.
     * `getReadWriteConfig()` then branches on `isset($config['write'][0])`: a list is several
     * configurations it picks one of at random, anything else is one fragment laid over the
     * connection. Either way the split itself is gone from the result, as it is from the framework's.
     *
     * @param  array<array-key, mixed>  $config
     * @return list<array<array-key, mixed>>
     */
    private static function writeSides(array $config): array
    {
        $write = $config['write'] ?? null;

        if (! isset($config['read']) || ! is_array($write)) {
            return [Arr::except($config, ['read', 'write'])];
        }

        $sides = [];

        foreach (isset($write[0]) ? $write : [$write] as $entry) {
            $sides[] = Arr::except(array_merge($config, is_array($entry) ? $entry : []), ['read', 'write']);
        }

        return $sides;
    }

    /**
     * A host value as a list, whatever shape it arrived in.
     *
     * @return list<string>
     */
    private static function hostsIn(mixed $host): array
    {
        $hosts = [];

        foreach (is_array($host) ? $host : [$host] as $candidate) {
            if (is_string($candidate) && $candidate !== '') {
                $hosts[] = $candidate;
            }
        }

        return $hosts;
    }
}
