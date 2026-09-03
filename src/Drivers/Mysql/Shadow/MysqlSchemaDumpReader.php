<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\Stages\StatementSplitter;
use Pushery\SQLens\Drivers\Mysql\Canonical\MysqlCanonicalization;

/**
 * Turns a Laravel `schema:dump` artifact into an ordered replay plan for the MySQL
 * shadow mode — the dump-specific layer ON TOP of the canonicalization
 * {@see StatementSplitter}, never a second splitter.
 *
 * Everything about SQL tokenization — string literals, backtick identifiers,
 * comments, backslash escapes, and the `DELIMITER` semantics a stored routine
 * needs — comes from the base splitter with the MySQL driver, so a semicolon inside
 * a string literal or a comment never splits a statement, and a routine body between
 * `DELIMITER $$` and `DELIMITER ;` stays one statement. This class adds only what a
 * DUMP carries beyond raw SQL:
 *
 *   - Dump preamble and comment lines (`-- …`, `# …`) glued to the front of the
 *     following statement are stripped; a statement that was ONLY comments is
 *     dropped as noise.
 *   - A whole-statement version-gated conditional comment — `/*!40101 SET … *​/`,
 *     `/*!40103 SET TIME_ZONE=… *​/`, and the trailing restore directives — is a
 *     client directive, not schema SQL. It is SKIPPED and recorded with its reason,
 *     never silently swallowed and never replayed. A conditional comment that only
 *     PREFIXES real DDL (a dumped trigger: `/*!50003 CREATE*​/ … TRIGGER … *​/`) is
 *     NOT a whole-statement directive and stays executable.
 *
 * Three-valued throughout: a dump that cannot be split safely (an unterminated
 * literal, an unknown delimiter) is a {@see DumpFailure} carrying the line, and a
 * missing or unreadable artifact is another — never a partial replay, because a
 * half-built shadow database is green with nothing behind it.
 */
final readonly class MysqlSchemaDumpReader
{
    private const string SKIPPED_DIRECTIVE_REASON = 'MySQL version-gated client directive; session state is not replayed into the shadow database';

    public function __construct(private StatementSplitter $splitter) {}

    /**
     * Read a dump file and split it. A missing or unreadable file is a named
     * failure, never treated as an empty dump.
     */
    public function read(string $path): SchemaDumpPlan|DumpFailure
    {
        $contents = is_file($path) ? file_get_contents($path) : false;

        if ($contents === false) {
            return DumpFailure::missing($path);
        }

        return $this->split($contents);
    }

    /**
     * Split a dump's text into an executable replay plan, or fail with a named
     * reason if it cannot be tokenized safely.
     */
    public function split(string $dump): SchemaDumpPlan|DumpFailure
    {
        $raw = $this->splitter->split($dump, new MysqlCanonicalization);

        if ($raw instanceof CanonicalizationFailure) {
            return DumpFailure::unparseable($dump, $raw);
        }

        $statements = [];
        $skipped = [];

        foreach ($raw as $rawStatement) {
            $statement = $this->stripLeadingComments($rawStatement);

            if ($statement === '') {
                // The statement was nothing but dump preamble or comment lines.
                continue;
            }

            if ($this->isWholeStatementDirective($statement)) {
                $skipped[] = new SkippedDumpDirective($statement, self::SKIPPED_DIRECTIVE_REASON);

                continue;
            }

            $statements[] = $statement;
        }

        return new SchemaDumpPlan($statements, $skipped);
    }

    /**
     * Strip leading whitespace and leading line comments (`-- …`, `# …`) — the form
     * a dump's preamble and inter-statement comments take once the base splitter has
     * glued them to the front of the following statement. A version-gated `/*! *​/`
     * directive is deliberately NOT stripped here: it is classified separately.
     */
    private function stripLeadingComments(string $statement): string
    {
        $statement = ltrim($statement);

        while ($statement !== '' && (str_starts_with($statement, '--') || str_starts_with($statement, '#'))) {
            $newline = strpos($statement, "\n");
            $statement = $newline === false ? '' : ltrim(substr($statement, $newline + 1));
        }

        return $statement;
    }

    /**
     * Whether the statement is entirely a single version-gated conditional comment
     * (`/*!##### … *​/` with nothing but whitespace after it) — a client directive to
     * skip. A conditional comment that only PREFIXES further SQL (its first `*​/` is
     * not at the end) is real DDL and returns false.
     */
    private function isWholeStatementDirective(string $statement): bool
    {
        if (! str_starts_with($statement, '/*!')) {
            return false;
        }

        $close = strpos($statement, '*/', 3);

        return $close !== false && rtrim(substr($statement, $close + 2)) === '';
    }
}
