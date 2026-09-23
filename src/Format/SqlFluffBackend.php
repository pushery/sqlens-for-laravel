<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Pushery\SQLens\Tools\ToolRunResult;

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
            '--nocolor',
            // No `--indent-unit` or `--indented-joins`: `sqlfluff format` knows neither, and
            // measured on 4.3.0 the call ends with exit 2 and "No such option", so every file would
            // come back refused. Layout values reach SQLFluff through the directives in input()
            // instead.
        ];
    }

    /**
     * Exit 1 with "Unfixable violations detected." and no parse error still carries the statement.
     *
     * Measured on 4.3.0: a `CREATE FUNCTION` of 124 characters on one line, under `max_line_length`
     * 100, ended with exit 1, that one sentence on stderr, and the statement on stdout with the
     * directives. `sqlfluff lint` names the rule, LT05 "Line is too long": SQLFluff formatted what it
     * could and found no place to break that line. Refused, every such file stayed undetermined and
     * kept `--check` red over a valid statement. What comes back still passes the output guard.
     *
     * A parse error exits 1 too, and says "templating/parsing errors found" first; that stays a
     * refusal in SQLFluff's words.
     */
    protected function completed(ToolRunResult $run): bool
    {
        return $run->exitCode === 0 || ($run->exitCode === 1
            && str_contains($run->stderrExcerpt, 'Unfixable violations detected.')
            && ! str_contains($run->stderrExcerpt, 'parsing errors found'));
    }

    /**
     * The statement with the style SQLFluff cannot take as flags, carried as its own directives.
     *
     * SQLFluff reads configuration from a comment in the text, measured on 4.3.0 for both values here:
     * `tab_space_size:2` indents by two, and `max_line_length:40` wraps a long WHERE that
     * `max_line_length:200` leaves on one line. Written on every run, the default included, because a
     * project's own `.sqlfluff` would otherwise decide what this package's style says, and in-file
     * directives are the one setting that file cannot override.
     *
     * AFTER the statement, not before it. A directive applies to the whole text wherever it stands,
     * and SQLFluff reports a refusal by line: two lines on top made `slect 1` a parse error on line 3
     * of a one-line file, and the refusal is passed through in the tool's own words. The newline in
     * front keeps a statement that ends in a comment from swallowing the first directive.
     */
    protected function input(string $sql, Dialect $dialect, FormatStyle $style): string
    {
        return $sql."\n".$this->directives($style);
    }

    /**
     * SQLFluff's output without the directives, with keyword case applied the way the core applies it.
     *
     * The separating newline goes with them when it is still there. SQLFluff drops it from a text with
     * nothing in front, measured on an empty statement, and keeps it everywhere else, so taking one
     * newline off when there is one gives the statement back with its own ending.
     *
     * `sqlfluff format` does not change keyword case, measured: a `capitalisation_policy:upper`
     * directive leaves `select` lower-case, because the formatter does not run the capitalisation
     * rules. So the case comes from the same tokenizer the PHP core formats with, and
     * `uppercase_keywords` means the same thing whichever of the two formatted a file. Output that
     * does not end in the directives is not the statement this backend handed over.
     */
    protected function output(string $stdout, Dialect $dialect, FormatStyle $style): ?string
    {
        $directives = $this->directives($style);

        if (! str_ends_with($stdout, $directives)) {
            return null;
        }

        $sql = substr($stdout, 0, -strlen($directives));

        if (str_ends_with($sql, "\n")) {
            $sql = substr($sql, 0, -1);
        }

        if (! $style->uppercaseKeywords) {
            return $sql;
        }

        return implode('', array_map(
            static fn (SqlToken $token): string => $token->mayUpperCaseIn($dialect) ? strtoupper($token->text) : $token->text,
            SqlTokenizer::tokenize($sql, $dialect),
        ));
    }

    public function unexpressible(FormatStyle $style): array
    {
        // SQLFluff's formatter takes its layout from configuration rather than from flags. Leading
        // commas ARE expressible there — through `.sqlfluff`, which is the project's file rather than
        // this package's, and reaching into it would mean a library editing a user's tool
        // configuration.
        return $style->leadingCommas ? ['leading_commas (set it in your own .sqlfluff instead)'] : [];
    }

    /** The in-file configuration lines this backend appends, each ending in a newline. */
    private function directives(FormatStyle $style): string
    {
        return '-- sqlfluff:indentation:tab_space_size:'.$style->indent."\n"
            .'-- sqlfluff:max_line_length:'.$style->lineWidth."\n";
    }
}
