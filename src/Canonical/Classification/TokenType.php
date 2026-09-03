<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Classification;

/**
 * What a classification token is: a keyword (a word in the driver's keyword list,
 * already upper-cased by keyword normalization) or an identifier (a quoted or bare,
 * possibly schema-qualified object reference). The classifier tokenizes the
 * canonical SQL into these two — symbols, literals, comments and dollar-bodies are
 * not tokens, as they carry no kind or target information.
 */
enum TokenType
{
    case Keyword;
    case Identifier;
}
