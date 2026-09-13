<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * One piece of a statement, with its source text kept verbatim.
 */
final readonly class SqlToken
{
    public function __construct(public SqlTokenKind $kind, public string $text) {}

    /**
     * Whether this is a SQL keyword, matched case-insensitively against a closed list.
     *
     * ⚠️ Only a {@see SqlTokenKind::Word} can be one. `"select"` is a column somebody named badly,
     * `'select'` is data, and `-- select` is a note — treating any of the three as a keyword is how a
     * formatter changes what a statement means.
     */
    public function isKeyword(): bool
    {
        return $this->kind === SqlTokenKind::Word && in_array(strtoupper($this->text), SqlKeywords::ALL, true);
    }

    /**
     * Whether a formatter may write this keyword in upper case for this dialect.
     *
     * A keyword on PostgreSQL always. On MySQL only a reserved one: an unreserved keyword can be a
     * table name, and MySQL on Linux compares table names by case. See SqlKeywords::MYSQL_UNRESERVED.
     */
    public function mayUpperCaseIn(Dialect $dialect): bool
    {
        return $this->isKeyword()
            && ($dialect !== Dialect::Mysql || ! in_array(strtoupper($this->text), SqlKeywords::MYSQL_UNRESERVED, true));
    }

    /**
     * Whether this is a comment that runs to the end of its line.
     *
     * The token that follows one has to start a new line, or it becomes part of the comment.
     */
    public function isLineComment(): bool
    {
        return $this->kind === SqlTokenKind::Comment && (str_starts_with($this->text, '--') || str_starts_with($this->text, '#'));
    }

    /** Whether this word starts a clause that a layout puts on its own line. */
    public function startsClause(): bool
    {
        return $this->kind === SqlTokenKind::Word && in_array(strtoupper($this->text), SqlKeywords::CLAUSE_STARTERS, true);
    }

    /** Whether this clause keyword is the second word of the clause the previous word opened: `LEFT JOIN`. */
    public function continuesClauseAfter(?self $previous): bool
    {
        return $previous instanceof self
            && $previous->kind === SqlTokenKind::Word
            && in_array(strtoupper($previous->text), SqlKeywords::CLAUSE_CONTINUATIONS[strtoupper($this->text)] ?? [], true);
    }
}
