<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

use Pushery\SQLens\Reporting\CredentialRedaction;
use Throwable;

/**
 * Both halves of credential redaction, in the one order that works.
 *
 * ## Why there are two halves at all
 *
 * {@see CredentialRedaction} knows what this project's connections are CONFIGURED with — the exact
 * password, url and dsn strings — and removes those wherever they appear. It cannot remove what it
 * was never told: a hostname the driver printed but the config spells differently, a role the
 * server named, a database the error quoted.
 *
 * {@see CredentialRedactor} knows the SHAPES the two drivers emit and removes coordinates by their
 * form. It cannot know that `hunter2` is a password when nothing around it says so.
 *
 * Each is blind exactly where the other sees, so a site that quotes words this package did not
 * write applies both.
 *
 * ## The order is not interchangeable
 *
 * Values first. A shape ends an unquoted value at the first delimiter, so run first it takes `abc`
 * out of `password=abc;def` and leaves `;def` behind, a part of the password that no longer matches
 * the configured value whole. Run first, the value pass removes the whole password wherever it
 * appears, and the shape pass then takes the coordinates that are left.
 *
 * ## Where it runs
 *
 * Wherever this package quotes words it did not write: the capture rules, the catalog readings, the
 * key counters a catalog reader could not read, the security run's notices, the error output of a
 * tool, and the audit's notice for an instance it cannot reach. Constructed without arguments it
 * reads the application's configured connections, so a site applies both halves without asking the
 * container for anything.
 *
 * Two kinds of site keep the shape half alone. A deploy check quotes an error into its reason, and
 * the preflight takes the configured values out of every reason when it returns its report, the
 * check's own prose included. And a configured URL shown through {@see CredentialRedactor::url()}
 * keeps its host, because a reader needs to know which address was meant. The `agent` reporter
 * applies the value half to the whole of its report.
 */
final readonly class CompositeCredentialRedactor
{
    public function __construct(
        private CredentialRedaction $values = new CredentialRedaction,
        private CredentialRedactor $shapes = new CredentialRedactor,
    ) {}

    public function redact(string $text): string
    {
        return $this->shapes->redact($this->values->in($text));
    }

    /** The same, for the common case where the text is an error's own words. */
    public function fromThrowable(Throwable $error): string
    {
        return $this->redact($error->getMessage());
    }
}
