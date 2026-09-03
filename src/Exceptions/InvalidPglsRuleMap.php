<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * The bundled Postgres Language Server rule map is not the shape the loader requires.
 *
 * A packaging error inside SQLens, never a user misconfiguration: the artifact ships with the
 * package and no application edits it. It fails by name at load rather than degrading, because
 * this map is what lets the package say which checks an absent binary costs you — and a map that
 * quietly lost entries would report a smaller loss than the real one, which is the direction that
 * makes the package look better and the user worse off.
 */
final class InvalidPglsRuleMap extends LogicException
{
    public static function unreadable(string $path): self
    {
        return new self(sprintf('The bundled Postgres Language Server rule map could not be read at "%s".', $path));
    }

    public static function unparsable(string $origin, string $detail): self
    {
        return new self(sprintf('The Postgres Language Server rule map "%s" is not valid JSON: %s', $origin, $detail));
    }

    public static function unsupportedSchemaVersion(string $origin, mixed $declared, int $supported): self
    {
        return new self(sprintf(
            'The Postgres Language Server rule map "%s" declares schema version %s; this build implements version %d.',
            $origin,
            is_scalar($declared) ? (string) $declared : strtoupper(get_debug_type($declared)),
            $supported,
        ));
    }

    public static function malformedKey(string $origin, string $path, string $expectation): self
    {
        return new self(sprintf('The Postgres Language Server rule map "%s" is malformed at "%s": expected %s.', $origin, $path, $expectation));
    }

    /**
     * An entry carries a field the loader does not know.
     *
     * Rejected rather than ignored: a typo in a field name would otherwise ship as a fact nobody
     * reads, and the entry would still look complete.
     */
    public static function unknownField(string $origin, string $rule, string $field): self
    {
        return new self(sprintf(
            'The Postgres Language Server rule map "%s" gives rule "%s" an unknown field "%s". A field nobody reads is a fact that silently does not apply.',
            $origin,
            $rule,
            $field,
        ));
    }

    /** An entry declares a severity outside the measured set. */
    public static function unknownSeverity(string $origin, string $rule, string $severity, string $allowed): self
    {
        return new self(sprintf(
            'The Postgres Language Server rule map "%s" gives rule "%s" the severity "%s". Measured: %s.',
            $origin,
            $rule,
            $severity,
            $allowed,
        ));
    }

    /** Two entries describe the same tool rule. */
    public static function duplicateRule(string $origin, string $rule): self
    {
        return new self(sprintf('The Postgres Language Server rule map "%s" describes the rule "%s" twice.', $origin, $rule));
    }

    /** The entries are not in the sorted order the artifact promises. */
    public static function unsorted(string $origin, string $rule): self
    {
        return new self(sprintf(
            'The Postgres Language Server rule map "%s" is not sorted by rule name — "%s" appears out of order. Without a stable order every diff is noise.',
            $origin,
            $rule,
        ));
    }
}
