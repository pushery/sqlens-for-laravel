<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * Whether a formatter's output still reads as the statement it was given.
 *
 * ## Why an external backend is checked at all
 *
 * pgFormatter and SQLFluff are better formatters than the built-in core, and neither is ours. Both
 * were measured writing a DIFFERENT statement: pgFormatter 5.11 turns `U&'d\0061t'` into
 * `U & 'd\0061t'`, a syntax error, and SQLFluff 4.3.0 on MySQL reads `5--1` as a comment and moves
 * it in front of the `SELECT`. A file is written from what the backend prints, so without a check
 * sqlens commits whatever a tool release gets wrong, and nothing in the run says so.
 *
 * ## What a formatter may change, and nothing more
 *
 * Both sides are read with the dialect's tokenizer, which splits tokens where the server does, and
 * compared in two sequences:
 *
 * - **Code.** Every token that is not whitespace or a comment, in order. A bare word may change case,
 *   because keywords and unquoted identifiers are case-insensitive to the server, and `!=` may become
 *   `<>`, which is the same operator. A string, a quoted identifier, a number or any other operator
 *   has to stay byte for byte.
 * - **Comments.** In order, with the whitespace inside them normalized. A comment may move to another
 *   line; it may not disappear, and code may not end up inside one — that shows up as a code token
 *   missing from the first sequence.
 *
 * The answer is a sentence about the first difference, because "the output was not used" without it
 * sends a reader to diff two statements by hand.
 */
final readonly class StatementIdentity
{
    /** How much of a token a difference quotes. */
    private const int QUOTED_LENGTH = 40;

    /** Null when `after` reads as the same statement as `before`, otherwise what changed first. */
    public static function firstDifference(string $before, string $after, Dialect $dialect): ?string
    {
        [$beforeCode, $beforeComments] = self::read($before, $dialect);
        [$afterCode, $afterComments] = self::read($after, $dialect);

        return self::compare($beforeCode, $afterCode, '')
            ?? self::compare($beforeComments, $afterComments, 'the comment ');
    }

    /**
     * The code tokens and the comments of a statement, each as [normalized, as written] pairs.
     *
     * A dollar-quoted body is compared as ONE token, byte for byte, unless the statement says it is
     * SQL or PL/pgSQL (`LANGUAGE sql`, `LANGUAGE plpgsql`, or a `DO` block without a language, which
     * is PL/pgSQL). Such a body is read like the statement around it, so pgFormatter may lay it out
     * and re-case its keywords. A body in any other language is data: reflowed Python is broken
     * Python, and nothing here can tell reflowed from broken.
     *
     * @return array{0: list<array{0: string, 1: string}>, 1: list<array{0: string, 1: string}>}
     */
    private static function read(string $sql, Dialect $dialect): array
    {
        $tokens = array_values(array_filter(
            SqlTokenizer::tokenize($sql, $dialect),
            static fn (SqlToken $token): bool => $token->kind !== SqlTokenKind::Whitespace,
        ));
        $sqlBodies = self::statementsWithSqlBodies($tokens);
        $code = [];
        $comments = [];
        $statement = 0;

        foreach ($tokens as $token) {
            if ($token->kind === SqlTokenKind::Comment) {
                $comments[] = [(string) preg_replace('/\s+/', ' ', trim($token->text)), $token->text];

                continue;
            }

            if ($token->kind === SqlTokenKind::String && isset($sqlBodies[$statement])
                && preg_match('/\A(\$[A-Za-z_0-9]*\$)(.*)\1\z/s', $token->text, $body) === 1) {
                [$bodyCode, $bodyComments] = self::read($body[2], $dialect);
                $code = [...$code, [$body[1], $body[1]], ...$bodyCode, [$body[1], $body[1]]];
                $comments = [...$comments, ...$bodyComments];

                continue;
            }

            $code[] = [match (true) {
                $token->kind === SqlTokenKind::Word => strtoupper($token->text),
                $token->text === '!=' => '<>',
                default => $token->text,
            }, $token->text];

            if ($token->text === ';') {
                $statement++;
            }
        }

        return [$code, $comments];
    }

    /**
     * The statements, by position, whose dollar-quoted bodies are SQL or PL/pgSQL.
     *
     * @param  list<SqlToken>  $tokens  without whitespace
     * @return array<int, true>
     */
    private static function statementsWithSqlBodies(array $tokens): array
    {
        $languages = [];
        $opensWithDo = [];
        $statement = 0;
        $first = true;

        foreach ($tokens as $i => $token) {
            if ($token->kind === SqlTokenKind::Comment) {
                continue;
            }

            if ($first) {
                $opensWithDo[$statement] = strtoupper($token->text) === 'DO';
                $first = false;
            }

            $next = $tokens[$i + 1] ?? null;

            if (strtoupper($token->text) === 'LANGUAGE' && $next instanceof SqlToken) {
                $languages[$statement] = strtolower(trim($next->text, "'\""));
            }

            if ($token->text === ';') {
                $statement++;
                $first = true;
            }
        }

        $sqlBodies = [];

        foreach ($opensWithDo + $languages as $position => $ignored) {
            $language = $languages[$position] ?? null;

            if (in_array($language, ['sql', 'plpgsql'], true) || ($language === null && ($opensWithDo[$position] ?? false))) {
                $sqlBodies[$position] = true;
            }
        }

        return $sqlBodies;
    }

    /**
     * @param  list<array{0: string, 1: string}>  $before
     * @param  list<array{0: string, 1: string}>  $after
     */
    private static function compare(array $before, array $after, string $what): ?string
    {
        $count = max(count($before), count($after));

        for ($i = 0; $i < $count; $i++) {
            $was = $before[$i] ?? null;
            $is = $after[$i] ?? null;

            if ($was === null) {
                return sprintf('%s%s was added', $what, self::quote($is[1] ?? ''));
            }

            if ($is === null) {
                return sprintf('%s%s is missing', $what, self::quote($was[1]));
            }

            if ($was[0] !== $is[0]) {
                return sprintf('%s%s became %s', $what, self::quote($was[1]), self::quote($is[1]));
            }
        }

        return null;
    }

    private static function quote(string $text): string
    {
        $flat = str_replace(["\r", "\n"], ['\\r', '\\n'], $text);

        return '"'.(mb_strlen($flat) > self::QUOTED_LENGTH ? mb_substr($flat, 0, self::QUOTED_LENGTH - 1).'…' : $flat).'"';
    }
}
