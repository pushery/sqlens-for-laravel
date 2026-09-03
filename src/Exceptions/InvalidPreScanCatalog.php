<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * The bundled pre-scan catalog artifact is not the shape the loader requires.
 *
 * This is a packaging error inside SQLens, never a user misconfiguration: the
 * artifact ships with the package and no application edits it. It exists so a
 * broken or half-migrated catalog fails by name at load — a catalog that quietly
 * lost half its entries would leave the pre-scan silently blind on exactly the
 * surfaces it was written to watch, which is the worst possible failure mode for
 * a "no silent green" tool.
 */
final class InvalidPreScanCatalog extends LogicException
{
    /** The artifact is not readable where the package expects it. */
    public static function unreadable(string $path): self
    {
        return new self(sprintf('The bundled pre-scan catalog could not be read at "%s".', $path));
    }

    /** The artifact is not valid JSON. */
    public static function unparsable(string $origin, string $detail): self
    {
        return new self(sprintf('The pre-scan catalog "%s" is not valid JSON: %s', $origin, $detail));
    }

    /** The artifact decoded to something other than an object. */
    public static function notAnObject(string $origin): self
    {
        return new self(sprintf('The pre-scan catalog "%s" must decode to a JSON object.', $origin));
    }

    /** The artifact declares a schema version this loader does not implement. */
    public static function unsupportedSchemaVersion(string $origin, mixed $declared, int $supported): self
    {
        return new self(sprintf(
            'The pre-scan catalog "%s" declares schema version %s; this build implements version %d.',
            $origin,
            // A scalar is shown as written; anything else — most importantly a
            // missing key, which arrives as null — is named by its TYPE, so the
            // message says "NULL" rather than an empty gap where a number belongs.
            is_scalar($declared) ? (string) $declared : strtoupper(get_debug_type($declared)),
            $supported,
        ));
    }

    /** A required key is missing or holds the wrong type. */
    public static function malformedKey(string $origin, string $path, string $expectation): self
    {
        return new self(sprintf('The pre-scan catalog "%s" is malformed at "%s": expected %s.', $origin, $path, $expectation));
    }

    /** A catalog the package asks for is not in the artifact. */
    public static function unknownCatalog(string $origin, string $name, string $available): self
    {
        return new self(sprintf(
            'The pre-scan catalog "%s" declares no catalog named "%s". It carries: %s.',
            $origin,
            $name,
            $available,
        ));
    }

    /** An entry carries an empty target. */
    public static function emptyTarget(string $origin): self
    {
        return new self(sprintf('The pre-scan catalog "%s" carries an entry with an empty target.', $origin));
    }

    /** An entry's target does not fit the documented target grammar. */
    public static function malformedTarget(string $origin, string $target): self
    {
        return new self(sprintf(
            'The pre-scan catalog "%s" carries the target "%s", which is not one of: Class::method, *::method, function(), Class, Namespace\\*.',
            $origin,
            $target,
        ));
    }

    /** Two entries in one catalog name the same target. */
    public static function duplicateTarget(string $origin, string $catalog, string $target): self
    {
        return new self(sprintf(
            'The pre-scan catalog "%s" lists the target "%s" twice in catalog "%s". A duplicate hides one of the two reasons.',
            $origin,
            $target,
            $catalog,
        ));
    }
}
