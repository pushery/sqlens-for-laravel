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
 * Each is blind exactly where the other sees, and the package had them wired to different callers:
 * the value pass ran on the `agent` reporter alone, the shape pass on a handful of translation
 * sites. Console, JSON, SARIF and GitHub got whichever one the producer happened to apply.
 *
 * ## The order is not interchangeable
 *
 * Values first. The shape pass rewrites its matches to `<redacted>`, so a configured password that
 * sat inside `password=hunter2` is gone before the value pass could recognize it — which is fine
 * for that occurrence and wrong for the general case: the same secret elsewhere in the message, in
 * a shape no pattern knows, would then survive. Running the value pass first removes every literal
 * occurrence, and the shape pass then takes the coordinates that are left.
 *
 * ## Why this is one object and not two calls at each site
 *
 * A composite assembled at the call site is a decision repeated at every call site, and the
 * finding this class comes from counted sixteen places that had made it differently. One object,
 * resolved from the container, is one decision.
 */
final readonly class CompositeCredentialRedactor
{
    public function __construct(
        private CredentialRedaction $values,
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
