<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * The config schema was asked about a path it does not declare — or about a
 * declared path in a role it does not have (a section asked for as if it were a
 * leaf value, a field asked for as if it belonged to an ignore entry).
 *
 * This is a programming error inside the package, never a user misconfiguration:
 * a user's bad key becomes a collected ConfigViolation, not an exception. It
 * exists so that adding a config key without declaring its schema fails with a
 * message naming the path, instead of PHP's bare UnhandledMatchError.
 */
final class UndeclaredConfigPath extends LogicException
{
    /** No expectation text is declared for this schema path. */
    public static function expectation(string $path): self
    {
        return new self(sprintf(
            'The config schema declares no expectation for the path "%s". Add an arm to ConfigSchema::expectation().',
            $path,
        ));
    }

    /** The path is not a leaf value — sections and entry shapes have no leaf validator. */
    public static function notALeaf(string $path): self
    {
        return new self(sprintf(
            'The config path "%s" is not a leaf value, so it has no leaf validation. Sections are walked key by key.',
            $path,
        ));
    }

    /** The field is not one an `ignore` entry may carry. */
    public static function notAnIgnoreField(string $field): self
    {
        return new self(sprintf(
            'The config schema declares no ignore-entry field "%s". Unknown fields are reported as violations, not validated.',
            $field,
        ));
    }
}
