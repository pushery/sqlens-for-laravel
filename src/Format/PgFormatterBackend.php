<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * pgFormatter (`pg_format`) — the best PostgreSQL formatter there is, when it is installed.
 *
 * ## PostgreSQL only, and it says so rather than trying
 *
 * pgFormatter is written for PostgreSQL's grammar. Pointed at MySQL it produces output that looks
 * formatted and quietly mangles backtick-quoted identifiers, which is worse than refusing — a
 * formatter that damages a statement while appearing to work is the failure this whole suite is
 * built to avoid. So `supports()` answers false for MySQL and the registry never reaches it.
 *
 * ## Two style options it cannot express, named up front
 *
 * `pg_format` has no leading-comma mode and no line-width bound. Reporting that BEFORE running is
 * the only honest answer: a project that asked for leading commas and got trailing ones would see
 * every file rewritten on the next run by whichever backend does honor the setting.
 */
final readonly class PgFormatterBackend extends ExternalSqlFormatter
{
    public function name(): string
    {
        return 'pgformatter';
    }

    public function supports(Dialect $dialect): bool
    {
        return $dialect === Dialect::Pgsql;
    }

    protected function arguments(Dialect $dialect, FormatStyle $style): array
    {
        return [
            // Read from STDIN, write to STDOUT. The alternative is naming files on the command line,
            // which makes the tool responsible for writing them — and this package writes its own
            // files through `SafeFileWriter`, for reasons that adapter's docblock states.
            '--spaces', (string) $style->indent,
            '--keyword-case', $style->uppercaseKeywords ? '2' : '0',
            '--nogrouping',
        ];
    }

    protected function unexpressibleOptions(FormatStyle $style): array
    {
        $missing = [];

        if ($style->leadingCommas) {
            $missing[] = 'leading_commas';
        }

        // Only when it was actually asked for something other than the shipped default. A backend
        // that refused every run because it cannot bound a line would be a backend nobody can use,
        // and the default is a value nobody chose.
        if ($style->lineWidth !== new FormatStyle()->lineWidth) {
            $missing[] = 'line_width';
        }

        return $missing;
    }
}
