<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers;

use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\ShippedLocale;

/**
 * The human-facing text for a driver-resolution failure.
 *
 * It names the driver and why it is out of scope, and it never quotes the DSN — the
 * sentence has to be safe to paste into an issue.
 *
 * ## What it does NOT do any more, and why the wording matters
 *
 * This block used to say the message "invites a contribution: unsupported here is a
 * statement about what has been built so far, not a refusal." For a RESERVED driver
 * that is false, and it was the last place still saying it. MariaDB, SQLite and SQL
 * Server are declared non-goals: `DriverRegistry::extend()` throws on their names, so
 * a reader who accepted the invitation would meet an exception. The shipped sentence
 * has said "the answer is settled" for a while; only this paragraph had not caught up.
 *
 * `unknown_driver` still invites one, and that invitation is the true one — there
 * `extend()` really does work, and only the three reserved names cannot.
 *
 * ## This class carries no rule id, deliberately
 *
 * A driver-resolution failure is not a FINDING. Every caller writes this sentence to
 * STDERR and stops; nothing reaches a report, so there is no row for an id to sit on.
 * A `RULE_ID` constant stood here for a while and nothing ever read it — cataloging
 * it would have documented a rule that can never appear in a report, which is worse
 * than the dead link it was meant to become.
 *
 * Only the SENTENCE is translated. The reason id and the documentation URL stay
 * English on the failure itself, because they reach the JSON envelope and a translated
 * identifier would be a breaking change per language.
 */
final readonly class UnsupportedDriverMessage
{
    public function __construct(private Translator $translator) {}

    public function for(DriverResolutionFailure $failure, string $connection, string $driver): string
    {
        // The failure supplies its OWN placeholder values, because only the factory
        // that built it knows what they mean. Filling them here from a single
        // `detail` string produced sentences like "reports version <the whole
        // sentence>, below the <the whole sentence> SQLens supports".
        return (string) $this->translator->get($failure->translationKey(), [
            'driver' => $driver,
            'connection' => $connection,
            ...$failure->placeholders,
        ], ShippedLocale::CODE);
    }
}
