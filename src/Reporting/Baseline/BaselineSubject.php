<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Baseline;

use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\LocationKind;

/**
 * The human-legible "where it was found" written on a baseline entry — legibility,
 * never identity (the fingerprint is the identity). It names the migration class, the
 * schema object, or the callsite method the finding addressed, per location kind.
 *
 * It is deliberately NOT a file path: the location's file is already repo-relative,
 * but a class or object name reads better in a diff and never risks leaking an
 * absolute path into the file. It is always non-empty — the serializer refuses a
 * blank subject — falling back to the location kind when a finding somehow carries no
 * name.
 */
final readonly class BaselineSubject
{
    public static function label(Location $location): string
    {
        $identity = self::identity($location);

        return $identity !== '' ? $identity : $location->kind->value;
    }

    /** The kind's identifying name, coerced to a string (empty when the finding lacks it). */
    private static function identity(Location $location): string
    {
        return match ($location->kind) {
            LocationKind::Migration => (string) $location->migrationClass,
            LocationKind::Catalog => (string) $location->objectName,
            LocationKind::Callsite => (string) $location->method,
        };
    }
}
