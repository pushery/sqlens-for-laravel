<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Why a `schema:dump` could not become a replay plan — the dump layer's
 * "no silent green". A half-replayed shadow database is the mode's most dangerous
 * state (green against half a schema), so a dump that cannot be read or split
 * safely stops the run with a named reason rather than replaying part of it.
 *
 * Two shapes: the artifact is missing or unreadable, and the artifact is present
 * but cannot be split (an unterminated literal, an unknown delimiter). The second
 * carries the 1-based `line` of the failing construct, computed from the offset the
 * splitter reports, so a user can find it.
 */
final readonly class DumpFailure
{
    private function __construct(
        public UndeterminedReason $reason,
        public string $detail,
        public ?int $line = null,
    ) {}

    public static function missing(string $path): self
    {
        return new self(
            UndeterminedReason::ShadowMysqlSchemaDumpMissing,
            sprintf('the schema dump at "%s" is missing or unreadable; run php artisan schema:dump', $path),
        );
    }

    /**
     * Build from a splitter failure, turning its byte offset into a 1-based line in
     * the dump. A failure with no offset (a driver that declares no split syntax)
     * reports no line rather than a guessed one.
     */
    public static function unparseable(string $dump, CanonicalizationFailure $failure): self
    {
        $line = $failure->offset === null
            ? null
            : substr_count(substr($dump, 0, $failure->offset), "\n") + 1;

        return new self(UndeterminedReason::ShadowMysqlDumpUnparseable, $failure->detail, $line);
    }
}
