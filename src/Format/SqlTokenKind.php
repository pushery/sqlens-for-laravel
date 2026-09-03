<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * What a token is, and therefore what a formatter may do to it.
 *
 * The distinction that matters is not grammatical, it is one of PERMISSION: three of these kinds are
 * verbatim and must survive formatting byte for byte, and the rest may be re-cased, re-spaced or
 * moved to another line.
 */
enum SqlTokenKind
{
    /** A bare word: keyword, identifier or number. The only kind a formatter may re-case. */
    case Word;

    /** A string literal, delimiters included. NEVER touched — its contents are data. */
    case String;

    /** An identifier in quotes or backticks. NEVER touched — the quoting is what makes it exact. */
    case QuotedIdentifier;

    /** A comment. NEVER touched: it can contain anything, including SQL that is not SQL. */
    case Comment;

    /** A run of whitespace. The one kind a formatter fully owns. */
    case Whitespace;

    /** `,` `(` `)` `;` — the structure a layout decision hangs on. */
    case Punctuation;

    /** Anything else, preserved verbatim because guessing at an operator is guessing at meaning. */
    case Operator;

    /** Whether a formatter is allowed to change this token's text at all. */
    public function isVerbatim(): bool
    {
        return in_array($this, [self::String, self::QuotedIdentifier, self::Comment], true);
    }
}
