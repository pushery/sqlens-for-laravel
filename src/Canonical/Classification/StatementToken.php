<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Classification;

/**
 * A single classification token. For a keyword, `text` is the upper-cased word; for
 * an identifier, `text` is the raw identifier reference exactly as it appears in the
 * canonical SQL (quoted or bare, possibly schema-qualified), ready to hand to
 * Identifier::parse.
 */
final readonly class StatementToken
{
    public function __construct(
        public TokenType $type,
        public string $text,
        /**
         * The last SYMBOL character before this token — `(`, `,`, `)`, `=` — or null when only
         * whitespace (or nothing) stood in front of it.
         *
         * The token stream deliberately drops punctuation, and for naming what a statement DOES
         * that is right: no kind and no target turns on a comma. One question does turn on it, and
         * it is the one a column list answers. Without this, `(a, b)` and `(a varchar_pattern_ops)`
         * are the SAME two identifier tokens, so an index carrying a non-default operator class
         * reads as a two-column index — and a foreign key on `(a)` then looks covered by an index
         * that answers no equality lookup at all. That is the silent, permanent direction of error
         * this package names as its cardinal sin, and one character of context is what tells the
         * two apart.
         *
         * A single character rather than the run of them: what a list element needs to know is
         * whether the thing immediately before it was a separator, and the last symbol is that.
         */
        public ?string $precededBy = null,
        /**
         * How many parentheses are open around this token — 0 at the top level of the statement.
         *
         * `precededBy` answers "what was immediately in front of me" and cannot answer "am I inside
         * something". The two questions look alike and one comma separates them: in
         * `SET a = f(x, y), b = 1`, both `y` and `b` are preceded by a comma, and only one of them
         * is an assignment target. Reading `y` as one would report a function argument as a written
         * column — a confident, specific, wrong answer, which is the shape this package refuses.
         *
         * It also RESCUES a case the depth-blind reading had to decline: in
         * `SET a = (SELECT …), b = 2` the keywords inside the subquery no longer end the clause,
         * because they are not at depth 0, so both assignments are captured instead of neither.
         *
         * Cheap to carry: the tokenizer already walks every character and records the last symbol.
         * Counting two of them is the same pass.
         */
        public int $depth = 0,
    ) {}
}
