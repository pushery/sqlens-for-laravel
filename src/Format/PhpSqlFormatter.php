<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

use Pushery\SQLens\Contracts\SqlFormatter;

/**
 * The formatter that is always there: pure PHP, no binary, no network, no install step.
 *
 * ## Why a built-in core exists beside two better external tools
 *
 * pgFormatter and SQLFluff both know more SQL than this ever will. Neither is installed on the
 * machine of somebody who just ran `composer require`, and a feature whose first experience is "the
 * tool you need is missing" is a feature most people never see working. This one runs everywhere,
 * every time, and its output is stable enough to commit.
 *
 * ## What it promises, precisely
 *
 * Consistent keyword casing, consistent indentation, one clause per line, and commas placed the way
 * a project asked. That is all. It does not re-order anything, does not rewrite expressions, and
 * does not touch a string literal, a quoted identifier or a comment — the three kinds of token where
 * changing a byte changes what the statement means.
 *
 * It is IDEMPOTENT: formatting formatted output returns the same bytes. That is not a nicety —
 * without it, a `--check` run and a `--write` run disagree about whether a file is clean, and every
 * commit rewrites every file.
 *
 * ## It is dialect-aware only where the dialects differ
 *
 * Which is: hardly anywhere, for these four decisions. Backtick-quoted identifiers are MySQL's and
 * double-quoted ones are PostgreSQL's, and both are already preserved verbatim by the tokenizer. So
 * this backend supports both dialects and says so, rather than declaring a difference it does not
 * have.
 */
final readonly class PhpSqlFormatter implements SqlFormatter
{
    public function name(): string
    {
        return 'php';
    }

    public function isAvailable(): bool
    {
        // Always. That is the entire reason this backend exists beside two better ones: it needs no
        // install step, so the first experience of `sqlens:format` is never "the tool you need is
        // missing".
        return true;
    }

    public function supports(Dialect $dialect): bool
    {
        // BOTH, and the reason is in the class docblock: the four decisions this backend makes are
        // the same in either dialect, and the one place they differ — identifier quoting — is a kind
        // of token it never touches.
        return true;
    }

    /**
     * The UTF-8 byte order mark, handled as a UNIT rather than as three characters of SQL.
     *
     * ⚠️ It was not, and the result was the worst class of bug this suite can have. The tokenizer
     * saw `EF`, `BB` and `BF` as three separate tokens and put a space between each, so a file that
     * opened with a BOM came back opening with `EF 20 BB 20 BF`: **a valid UTF-8 file rewritten as
     * an invalid one**. The run reported success, and because the damaged form is itself stable,
     * every later `--check` called the file clean. Nothing anywhere would have said what happened.
     */
    private const string BYTE_ORDER_MARK = "\xEF\xBB\xBF";

    public function format(string $sql, Dialect $dialect, FormatStyle $style): FormatResult
    {
        // Taken off the front BEFORE anything looks at the SQL, and put back on the end. The marker
        // is a fact about the FILE — which encoding it announces — and not a token of the statement,
        // so no rule in this class has any business seeing it. Re-attached rather than re-created:
        // a file that had none must not acquire one, or the first run would add three bytes to every
        // `.sql` file in the repository.
        $mark = str_starts_with($sql, self::BYTE_ORDER_MARK) ? self::BYTE_ORDER_MARK : '';

        if ($mark !== '') {
            $sql = substr($sql, strlen(self::BYTE_ORDER_MARK));
        }

        // Checked BEFORE any work, the way the external backends check theirs, and conditional for
        // the reason PgFormatterBackend states about the same option: a core that refused every run
        // because it cannot bound a line would be a core nobody can use, and the shipped default is
        // a value nobody chose.
        //
        // ⚠️ Until this existed, `line_width` was read from config, validated, and folded into the
        // style FINGERPRINT — and then ignored. Measured: 20, 100 and 400 gave byte-identical
        // output. A project that set it saw its report claim a different style and its files come
        // back the same, which is precisely the silent drop {@see FormatUndeterminedReason::StyleNotExpressible}
        // exists to prevent. Wrapping to a column is a real feature and may arrive later; saying
        // nothing was never an option.
        if ($style->lineWidth !== new FormatStyle()->lineWidth) {
            return FormatResult::undetermined(
                FormatUndeterminedReason::StyleNotExpressible,
                $this->name(),
                $dialect,
                $style,
                'this backend cannot express: line_width (it breaks on structure, not on a column; '
                    .'use the pgformatter or sqlfluff backend if you need a width)',
            );
        }

        $trimmed = trim($sql);

        if ($trimmed === '') {
            // Not a failure and not formatted output either: there was nothing to format. Answering
            // with an empty string would make a `--check` run report an empty file as reformatted on
            // every single run.
            return FormatResult::undetermined(
                FormatUndeterminedReason::Unparsable,
                $this->name(),
                $dialect,
                $style,
                'the statement is empty, so there is nothing to format',
            );
        }

        // Whitespace is DROPPED before the layout loop rather than skipped inside it, and that is
        // not a tidiness choice: with it in the list, "the previous token" is whitespace wherever
        // the author happened to type a space, so every look-back — is the previous token a comma,
        // is it a function name — silently answers about the space instead. Measured: the trailing
        // comma never broke a line, because the token before the break candidate was never the
        // comma.
        //
        // Dropping them is safe precisely because this formatter writes every space in its output
        // itself, which is also what makes the result idempotent.
        $tokens = array_values(array_filter(
            SqlTokenizer::tokenize($trimmed),
            static fn (SqlToken $token): bool => $token->kind !== SqlTokenKind::Whitespace,
        ));

        $out = '';
        $depth = 0;
        $atLineStart = true;

        // Carried rather than indexed back into `$tokens`, so the "there is no previous token" case
        // is a value this loop can see instead of a branch inside the spacing rule that no run can
        // reach — the first token is always at a line start, so the rule was never asked about it.
        $previous = null;

        foreach ($tokens as $index => $token) {
            if ($token->text === ')') {
                $depth = max(0, $depth - 1);
            }

            $breaks = ! $atLineStart && $this->breaksBefore($token, $tokens, $index, $style);

            if ($breaks) {
                $out .= "\n".str_repeat(' ', $style->indent * $depth);
                $atLineStart = true;
            }

            if ($previous instanceof SqlToken && ! $atLineStart && $this->spaceBefore($token, $previous)) {
                $out .= ' ';
            }

            $out .= $this->render($token, $style);
            $atLineStart = false;
            $previous = $token;

            if ($token->text === '(') {
                $depth++;
            }
        }

        return FormatResult::formatted($mark.$out, $this->name(), $dialect, $style);
    }

    /**
     * How a token is written out — the ONLY place casing changes.
     *
     * Guarded twice over: `isKeyword()` is false for anything that is not a bare word, and this
     * checks the verbatim kinds again. Two guards for one rule looks redundant and is not — a
     * formatter that upper-cases the inside of a string literal has corrupted data, and that is the
     * one bug this class must not have.
     */
    private function render(SqlToken $token, FormatStyle $style): string
    {
        if ($token->kind->isVerbatim()) {
            return $token->text;
        }

        return $style->uppercaseKeywords && $token->isKeyword() ? strtoupper($token->text) : $token->text;
    }

    /**
     * Whether this token starts a new line.
     *
     * Three cases, and the comma is the interesting one: with leading commas the break comes BEFORE
     * the comma, and with trailing commas AFTER it — which is the same decision seen from either
     * side, and the reason both are one branch rather than two features.
     *
     * @param  list<SqlToken>  $tokens
     */
    private function breaksBefore(SqlToken $token, array $tokens, int $index, FormatStyle $style): bool
    {
        if ($token->startsClause()) {
            return true;
        }

        if ($style->leadingCommas && $token->text === ',') {
            return true;
        }

        if (! $style->leadingCommas && ($tokens[$index - 1] ?? null)?->text === ',') {
            return true;
        }

        // A comment keeps its own line. Appending one to the end of a formatted clause would put a
        // `--` comment in front of everything that followed it on that line — which comments out
        // working SQL, the one class of change a formatter must never make.
        return $token->kind === SqlTokenKind::Comment;
    }

    /**
     * Whether a space goes before this token.
     *
     * The list of things a space does NOT go before is short and each entry is a real shape:
     * `count(*)` not `count (*)`, `id,` not `id ,`, `);` not `) ;`.
     *
     * `$previous` is non-nullable on purpose: the caller only asks once something has been written,
     * so "no previous token" is its state to hold rather than a case for this rule to re-check.
     */
    private function spaceBefore(SqlToken $token, SqlToken $previous): bool
    {
        if (in_array($token->text, [',', ';', ')'], true)) {
            return false;
        }

        // After an opening paren, never. `(id` and not `( id`.
        if ($previous->text === '(') {
            return false;
        }

        // A function call: `count(` and not `count (`. Only when the previous token is a WORD —
        // `in (` keeps its space, because `in` is a keyword and `in(` reads as a call to something.
        return ! ($token->text === '(' && $previous->kind === SqlTokenKind::Word && ! $previous->isKeyword());
    }
}
