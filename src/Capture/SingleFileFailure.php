<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

/**
 * Why a `--file` fast-path run could not name its one subject. Every case is a
 * misconfiguration, not a skip and never a silent empty result: `--file` is a
 * deliberate request to lint one migration, so a path that does not resolve to one
 * is a named error the user has to fix, not a run that quietly checked nothing.
 *
 * `--file` is not a general-purpose file linter — a path outside the configured
 * migration paths is refused rather than captured, so the fast path can never be
 * pointed at an arbitrary file on disk.
 */
enum SingleFileFailure: string
{
    case NotFound = 'not_found';
    case NotPhp = 'not_php';
    case OutsideMigrationPaths = 'outside_migration_paths';

    /** The translation key for the user-facing message, under the commands group. */
    public function translationKey(): string
    {
        return match ($this) {
            self::NotFound => 'sqlens::messages.commands.file_not_found',
            self::NotPhp => 'sqlens::messages.commands.file_not_php',
            self::OutsideMigrationPaths => 'sqlens::messages.commands.file_outside_paths',
        };
    }
}
