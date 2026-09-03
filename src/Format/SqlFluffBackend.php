<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * SQLFluff — a linter that also formats, and the only one here that answers for both dialects.
 *
 * ## Why it sits BELOW pgFormatter in the auto order
 *
 * On PostgreSQL, pgFormatter is better at the thing both do. SQLFluff earns its place by covering
 * MySQL as well, which pgFormatter does not — so a project on MySQL gets a real formatter rather
 * than the built-in core, and a project on PostgreSQL gets the better of the two.
 *
 * ## The dialect is passed through, never assumed
 *
 * SQLFluff formats to whichever dialect it is told, and told nothing it picks a default that is
 * neither of the two this package supports. A run that omitted the flag would produce output shaped
 * for a third grammar — plausible, committed, and wrong in ways nobody would attribute to a missing
 * argument.
 */
final readonly class SqlFluffBackend extends ExternalSqlFormatter
{
    public function name(): string
    {
        return 'sqlfluff';
    }

    public function supports(Dialect $dialect): bool
    {
        return true;
    }

    protected function arguments(Dialect $dialect, FormatStyle $style): array
    {
        return [
            'format',
            // STDIN, and the dialect stated explicitly. Told nothing, SQLFluff picks a default that
            // is neither of the two dialects this package supports.
            '-',
            '--dialect', $dialect === Dialect::Pgsql ? 'postgres' : 'mysql',
            '--indent-unit', 'space',
            '--indented-joins',
            '--nocolor',
        ];
    }

    protected function unexpressibleOptions(FormatStyle $style): array
    {
        // SQLFluff's formatter takes its layout from a config file rather than from flags, so the
        // two options this package can pass are the two it passes. Leading commas ARE expressible
        // there — through `.sqlfluff`, which is the project's file rather than this package's, and
        // reaching into it would mean a library editing a user's tool configuration.
        return $style->leadingCommas ? ['leading_commas (set it in your own .sqlfluff instead)'] : [];
    }
}
