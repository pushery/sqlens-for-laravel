<?php

declare(strict_types=1);

namespace Pushery\SQLens;

/**
 * The one language this package speaks: US English, on every machine, under every host app.
 *
 * ## Why a constant and not "whatever the app is set to"
 *
 * This package writes to a terminal, a CI annotation, a SARIF file and an agent artifact. Every one
 * of those is read by somebody debugging a database at an awkward hour, or by a machine. None of
 * them is a user interface, and none of them gets better in a second language — a translated
 * `ALTER TABLE` warning still contains `ALTER TABLE`, and a reader who can act on it reads the SQL
 * either way. The owner's decision, 2026-08-12: shell output stays US English, one spelling,
 * everywhere.
 *
 * ## Why the locale is passed EXPLICITLY at every resolution point
 *
 * This is the part that is not cosmetic, and it was measured rather than assumed.
 *
 * With only `lang/en` present, Laravel's translator resolves a missing locale through
 * `app.fallback_locale`. That works for the common setup and fails for one that is perfectly
 * ordinary: an app that sets BOTH `app.locale` and `app.fallback_locale` to its own language — a
 * German shop setting `de`/`de` — has no path to English at all, so `Translator::get()` returns the
 * key it was given. Measured on this tree: `locale=de fallback=en` yields the sentence,
 * `locale=de fallback=de` yields the literal string
 * `sqlens::messages.drivers.reserved_driver`, printed where a sentence should be.
 *
 * Nothing about that is red. The package has no opinion about the host's locale config, the
 * translator does exactly what it documents, and the only symptom is a user seeing a dotted token
 * in their terminal. So the locale is not left to be inferred: every call passes this constant, and
 * `tests/Feature/Localization/ShippedLocaleTest.php` holds the host-locale cases that used to leak.
 *
 * Its sibling `tests/Unit/LocaleParityTest.php` holds the other half — that `en` is the ONLY locale
 * shipped — so a re-added translation cannot quietly reintroduce the second language this constant
 * exists to rule out.
 */
final readonly class ShippedLocale
{
    /**
     * The locale every message of this package resolves under, regardless of the host app.
     *
     * Passed as the third argument of `Translator::get()` at each of the resolution points. That
     * argument also disables the fallback chain by making it unnecessary — the locale asked for is
     * the locale that exists.
     */
    public const string CODE = 'en';
}
