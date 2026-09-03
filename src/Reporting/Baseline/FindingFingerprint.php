<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use Pushery\SQLens\Canonical\Fingerprint;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Subjects\MigrationDirection;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The stable identity a baseline entry recognizes a finding by. Without it, a
 * baseline would rot on every reformat and the whole feature would be worthless.
 *
 * The identity is deliberately free of positional noise: NO line number and NO
 * statement index, so a change ABOVE a finding never shifts its fingerprint. It is
 * built from the rule id, the normalized location (repo-relative, forward-slashed
 * path plus the migration class or the catalog object name — never an absolute path
 * or a hostname), and the CANONICAL excerpt hash from the canonicalization layer —
 * never raw grammar output. That last part is why canonicalization is a foundation,
 * not a by-product: the same statement in different quoting or whitespace produces
 * the same canonical form, so it produces the same fingerprint, and a Laravel
 * grammar change cannot invalidate a whole baseline at once.
 *
 * Two genuinely different findings get different fingerprints (different excerpt or
 * location); several identical findings in one subject share a fingerprint and are
 * told apart by a separate, deterministic ordinal on the baseline entry.
 */
final readonly class FindingFingerprint
{
    private function __construct(public string $value) {}

    public static function of(string $ruleId, Location $location, Fingerprint $excerpt): self
    {
        $parts = [
            $ruleId,
            ...self::normalizedLocation($location),
            $excerpt->value,
        ];

        return new self(hash('sha256', implode("\x1f", $parts)));
    }

    /**
     * Rebuild a fingerprint from a value read back out of a baseline file. The
     * shape is validated rather than trusted: a truncated or hand-edited value
     * would silently match nothing, which reads exactly like "this finding is new"
     * and would quietly un-suppress an accepted finding.
     */
    public static function fromStored(string $value): ?self
    {
        return preg_match('/^[0-9a-f]{64}$/', $value) === 1 ? new self($value) : null;
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->value, $other->value);
    }

    /**
     * The identity-bearing location fields, in a fixed order. Line and statement
     * index are DELIBERATELY absent (positional noise); the path is forced to
     * forward slashes so macOS, Linux, and Windows agree on one fingerprint.
     *
     * @return list<string>
     */
    private static function normalizedLocation(Location $location): array
    {
        return [
            $location->kind->value,
            self::forwardSlash($location->file),
            $location->migrationClass ?? '',
            $location->direction instanceof MigrationDirection ? $location->direction->value : '',
            $location->driver ?? '',
            $location->instance ?? '',
            $location->objectName ?? '',
            $location->objectType instanceof SchemaObjectType ? $location->objectType->value : '',
            $location->method ?? '',
        ];
    }

    private static function forwardSlash(?string $path): string
    {
        return $path === null ? '' : str_replace('\\', '/', $path);
    }
}
