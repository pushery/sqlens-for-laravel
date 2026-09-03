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

    /** Whether this word starts a clause that a layout puts on its own line. */
    public function startsClause(): bool
    {
        return $this->kind === SqlTokenKind::Word && in_array(strtoupper($this->text), SqlKeywords::CLAUSE_STARTERS, true);
    }
}
