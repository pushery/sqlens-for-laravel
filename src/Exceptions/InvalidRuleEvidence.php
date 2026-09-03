<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The bundled rule-evidence register could not be read as written.
 *
 * Every constructor names the exact field, because the alternative — a lenient read
 * that returns what it could parse — would leave a rule silently evidence-free, and the
 * completeness check meant to catch that would then pass over the gap.
 */
final class InvalidRuleEvidence extends RuntimeException
{
    public static function unreadable(string $path): self
    {
        return new self("The rule-evidence register \"{$path}\" could not be read.");
    }

    public static function unparsable(string $path, string $reason): self
    {
        return new self("The rule-evidence register \"{$path}\" is not valid JSON: {$reason}");
    }

    public static function unsupportedSchemaVersion(string $origin, mixed $declared, int $supported): self
    {
        return new self(sprintf(
            'The rule-evidence register "%s" declares schema version %s; this build implements version %d.',
            $origin,
            // A scalar is shown as written; anything else — a missing key arrives as
            // null — is named by its TYPE, so the message says "NULL" rather than
            // leaving an empty gap where a number belongs.
            is_scalar($declared) ? (string) $declared : strtoupper(get_debug_type($declared)),
            $supported,
        ));
    }

    public static function malformed(string $origin, string $field, string $expectation): self
    {
        return new self("The rule-evidence register \"{$origin}\" needs {$expectation} at {$field}.");
    }
}
