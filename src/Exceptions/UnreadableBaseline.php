<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A baseline file exists but cannot be read with confidence. Every case here maps
 * to the misconfiguration exit status, never to a run that continues.
 *
 * That strictness is the whole point. A baseline decides which findings are
 * suppressed, so half-understanding one is worse than not having it: reading it
 * loosely could suppress findings the user never accepted, and ignoring it
 * silently could drown them in findings they did accept. Both are silent, and
 * both are wrong — so the run stops and says which file and why.
 */
final class UnreadableBaseline extends RuntimeException
{
    public static function notAnObject(string $path, string $found): self
    {
        return new self(sprintf(
            'The baseline at "%s" is not a JSON object (found %s). Regenerate it with sqlens:baseline.',
            $path,
            $found,
        ));
    }

    public static function missingVersion(string $path, string $versionKey): self
    {
        return new self(sprintf(
            'The baseline at "%s" carries no "%s" field, so its format cannot be determined. SQLens does not guess a version. Regenerate it with sqlens:baseline.',
            $path,
            $versionKey,
        ));
    }

    public static function versionNotAnInteger(string $path, string $versionKey, string $found): self
    {
        return new self(sprintf(
            'The baseline at "%s" has a "%s" of %s, but the schema version must be an integer.',
            $path,
            $versionKey,
            $found,
        ));
    }

    public static function writtenByNewerVersion(string $path, int $found, int $supported): self
    {
        return new self(sprintf(
            'The baseline at "%s" was written by a newer SQLens version (schema version %d; this build reads %d). Upgrade SQLens or regenerate the baseline.',
            $path,
            $found,
            $supported,
        ));
    }

    public static function versionNoLongerRead(string $path, int $found, int $supported): self
    {
        return new self(sprintf(
            'The baseline at "%s" uses schema version %d, which this build no longer reads (it reads %d) and for which no migration path exists. Regenerate it with sqlens:baseline.',
            $path,
            $found,
            $supported,
        ));
    }

    /** @param  list<string>  $unknown */
    public static function unknownRootFields(string $path, array $unknown, string $known): self
    {
        return new self(sprintf(
            'The baseline at "%s" carries unknown top-level field(s): %s. This build cannot honor them, and ignoring them could silently change which findings are suppressed. Expected only: %s.',
            $path,
            implode(', ', $unknown),
            $known,
        ));
    }

    public static function missingRootField(string $path, string $field): self
    {
        return new self(sprintf(
            'The baseline at "%s" is missing the required top-level field "%s".',
            $path,
            $field,
        ));
    }

    public static function entriesNotAList(string $path, string $found): self
    {
        return new self(sprintf(
            'The baseline at "%s" has "entries" of %s, but it must be a JSON array of entries.',
            $path,
            $found,
        ));
    }

    public static function invalidJson(string $path, string $reason): self
    {
        return new self(sprintf('The baseline at "%s" is not valid JSON: %s', $path, $reason));
    }

    public static function entryNotAnObject(string $path, int $index, string $found): self
    {
        return new self(sprintf(
            'Entry %d of the baseline at "%s" is %s, but every entry must be a JSON object.',
            $index,
            $path,
            $found,
        ));
    }

    public static function entryMissingField(string $path, int $index, string $field): self
    {
        return new self(sprintf(
            'Entry %d of the baseline at "%s" is missing the field "%s".',
            $index,
            $path,
            $field,
        ));
    }

    public static function entryUnknownField(string $path, int $index, string $field, string $known): self
    {
        return new self(sprintf(
            'Entry %d of the baseline at "%s" carries the unknown field "%s". Expected only: %s.',
            $index,
            $path,
            $field,
            $known,
        ));
    }

    public static function entryFieldOutOfShape(string $path, int $index, string $field, string $expected, string $found): self
    {
        return new self(sprintf(
            'Entry %d of the baseline at "%s" has a "%s" of %s, but it must be %s.',
            $index,
            $path,
            $field,
            $found,
            $expected,
        ));
    }
}
