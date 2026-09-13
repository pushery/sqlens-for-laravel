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
 * ## Two style options it refuses, named up front
 *
 * ⚠️ This paragraph said `pg_format` has no leading-comma mode and no line-width bound. It has both,
 * `--comma-start` and `--wrap-limit`, and neither produces the style the option names. Measured on
 * pg_format 5.11:
 *
 * - `--comma-start` puts the commas of a SELECT list first, and rewrites every comma inside
 *   parentheses as ` , `: `coalesce(a , b)`, `IN ('open' , 'pending')`.
 * - `--wrap-limit 60` breaks a long `IN` list, indents the continuation lines with a TAB whatever
 *   `--spaces` says, and breaks far below the limit (lines of 32 to 37 characters).
 *
 * So both are refused, and BEFORE running: a project that asked for leading commas and got the
 * spaced ones, or asked for a width and got tabs, would see every file rewritten on the next run by
 * whichever backend does honor the setting. `auto` passes this backend over for such a style.
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
            // ⚠️ Without `--no-rcfile`, pg_format reads `./.pg_format`, `$HOME/.pg_format` and its XDG
            // file, and every option this list does not set comes from there. Measured: a `.pg_format`
            // with `function-case=2` in the working directory turned `count(id)` into `COUNT(id)`. The
            // same file may say `anonymize=1`, which replaces literals, or `nocomment=1` or `maxlength`.
            // Two machines would format one file differently, so the style configured in sqlens is the
            // whole of what this backend is told.
            '--no-rcfile',
            // Parentheses stay as written. By default pg_format drops what it considers redundant in
            // DML (`where ((b = 1))` became `WHERE (b = 1)`), and a formatter here rewrites no expression.
            '--redundant-parenthesis',
        ];
    }

    public function unexpressible(FormatStyle $style): array
    {
        $missing = [];

        if ($style->leadingCommas) {
            $missing[] = 'leading_commas';
        }

        // Only when it was actually asked for something other than the shipped default. A backend
        // that refused every run over a width nobody chose would be a backend nobody can use.
        if ($style->lineWidth !== new FormatStyle()->lineWidth) {
            $missing[] = 'line_width';
        }

        return $missing;
    }
}
