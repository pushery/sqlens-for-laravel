<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Settings;

/**
 * The shipped expectations, read once and asked by variable.
 *
 * Same shape as the other bundled registers: a file under `resources/data`, loaded here, so a rule
 * asks a question instead of carrying an answer. What makes this one worth a class rather than an
 * array is the VERSION dimension — an entry holds from `min_version` on, and asking without a
 * version would silently return an expectation that does not apply to the server in front of you.
 */
final readonly class ServerSettingMatrix
{
    public const string BUNDLED_FILE = 'resources/data/server-settings.json';

    /** @param  list<ServerSettingExpectation>  $entries */
    private function __construct(public array $entries) {}

    /** The shipped matrix. */
    public static function bundled(): self
    {
        return self::fromFile(dirname(__DIR__, 3).'/'.self::BUNDLED_FILE);
    }

    public static function fromFile(string $path): self
    {
        $raw = is_file($path) ? file_get_contents($path) : false;
        $decoded = $raw === false ? null : json_decode($raw, true);
        $rows = is_array($decoded) && is_array($decoded['entries'] ?? null) ? $decoded['entries'] : [];

        $entries = [];

        foreach ($rows as $row) {
            // Keyed by string or skipped. A row that is not a string-keyed array is not a partial
            // entry to salvage — it is a file somebody hand-edited into a shape this cannot read,
            // and guessing at it would put an invented expectation in front of a rule.
            if (is_array($row)) {
                /** @var array<string, mixed> $row */
                $entries[] = ServerSettingExpectation::fromArray($row);
            }
        }

        return new self($entries);
    }

    /**
     * The expectation for one variable on one server, or null when the matrix has nothing for it.
     *
     * Null is not "no expectation" — that is what an entry with a null `expectation` says. This is
     * "the matrix does not cover this", and a rule reaching it should report that it could not
     * check rather than assume the value is fine.
     */
    public function for(string $driver, string $variable, ?string $serverVersion = null): ?ServerSettingExpectation
    {
        foreach ($this->entries as $entry) {
            if ($entry->driver !== $driver) {
                continue;
            }
            if ($entry->variable !== $variable) {
                continue;
            }
            if ($serverVersion !== null && ! $this->covers($entry, $serverVersion)) {
                continue;
            }

            return $entry;
        }

        return null;
    }

    /**
     * Whether the entry's version window contains this server.
     *
     * Compared with `version_compare`, not numerically: `8.4` and `8.10` are not decimals, and a
     * numeric comparison would put the later release first — a mistake that shows up only once a
     * two-digit minor exists, which is exactly when nobody is looking for it.
     */
    private function covers(ServerSettingExpectation $entry, string $serverVersion): bool
    {
        if (version_compare($serverVersion, $entry->minVersion, '<')) {
            return false;
        }

        return $entry->maxVersion === null || version_compare($serverVersion, $entry->maxVersion, '<=');
    }
}
