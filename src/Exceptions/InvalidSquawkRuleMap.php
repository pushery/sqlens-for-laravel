<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * The bundled Squawk rule map is not the shape the loader requires.
 *
 * A packaging error inside SQLens, never a user misconfiguration: the artifact ships with the
 * package and no application edits it. It fails by name at load because the map is the only
 * thing that knows which of the tool's findings SQLens already reports itself — a map that
 * quietly lost half its entries would turn de-duplication off for exactly those rules and
 * report every one of them twice, which reads as thoroughness rather than as a defect.
 */
final class InvalidSquawkRuleMap extends LogicException
{
    public static function unreadable(string $path): self
    {
        return new self(sprintf('The bundled Squawk rule map could not be read at "%s".', $path));
    }

    public static function unparsable(string $origin, string $detail): self
    {
        return new self(sprintf('The Squawk rule map "%s" is not valid JSON: %s', $origin, $detail));
    }

    public static function unsupportedSchemaVersion(string $origin, mixed $declared, int $supported): self
    {
        return new self(sprintf(
            'The Squawk rule map "%s" declares schema version %s; this build implements version %d.',
            $origin,
            is_scalar($declared) ? (string) $declared : strtoupper(get_debug_type($declared)),
            $supported,
        ));
    }

    public static function malformedKey(string $origin, string $path, string $expectation): self
    {
        return new self(sprintf('The Squawk rule map "%s" is malformed at "%s": expected %s.', $origin, $path, $expectation));
    }

    /**
     * An entry carries a field the loader does not know.
     *
     * Rejected rather than ignored, which is the whole reason this case exists: a typo in a field
     * name would otherwise ship as a fact nobody reads, and the entry would look complete.
     */
    public static function unknownField(string $origin, string $rule, string $field): self
    {
        return new self(sprintf(
            'The Squawk rule map "%s" gives rule "%s" an unknown field "%s". A field nobody reads is a fact that silently does not apply.',
            $origin,
            $rule,
            $field,
        ));
    }

    /** An entry points at a SQLens rule id that does not exist. */
    public static function unknownSqlensRule(string $origin, string $rule, string $sqlensRule): self
    {
        return new self(sprintf(
            'The Squawk rule map "%s" maps "%s" onto the SQLens rule "%s", which is not in the rule registry.',
            $origin,
            $rule,
            $sqlensRule,
        ));
    }

    /** An entry declares a parity status outside the closed set. */
    public static function unknownParityStatus(string $origin, string $rule, string $status, string $allowed): self
    {
        return new self(sprintf(
            'The Squawk rule map "%s" gives rule "%s" the parity status "%s". Allowed: %s.',
            $origin,
            $rule,
            $status,
            $allowed,
        ));
    }

    /** Two entries describe the same tool rule. */
    public static function duplicateRule(string $origin, string $rule): self
    {
        return new self(sprintf('The Squawk rule map "%s" describes the rule "%s" twice.', $origin, $rule));
    }

    /** The entries are not in the sorted order the artifact promises. */
    public static function unsorted(string $origin, string $rule): self
    {
        return new self(sprintf(
            'The Squawk rule map "%s" is not sorted by rule name — "%s" appears out of order. Without a stable order every diff is noise.',
            $origin,
            $rule,
        ));
    }
}
