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
 * Three shapes: the artifact is missing or unreadable, the artifact is present
 * but cannot be split (an unterminated literal, an unknown delimiter), and it holds
 * a statement the replay refuses. The last two carry the 1-based `line` of the
 * failing construct where it is known, so a user can find it.
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
     * A statement the replay refuses, named by its leading words and its line and never by its
     * text: a refused `CREATE USER … IDENTIFIED BY …` carries a password, and this detail reaches a
     * log.
     */
    public static function refused(string $form, string $why, ?int $line): self
    {
        return new self(UndeterminedReason::ShadowMysqlDumpRefused, sprintf('`%s` %s', $form, $why), $line);
    }

    /** What a person reading the log needs: the detail, and the line when there is one. */
    public function diagnosis(): string
    {
        return $this->line === null ? $this->detail : sprintf('%s (line %d of the dump)', $this->detail, $this->line);
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
