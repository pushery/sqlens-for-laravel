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
 *   - A whole-statement version-gated conditional comment is read by what it
 *     CONTAINS, because the server executes it like any other statement:
 *       - A `SET` inside one — `/*!40101 SET … *​/`, `/*!40103 SET TIME_ZONE=… *​/`,
 *         the trailing restore directives — is session state, not schema SQL. It is
 *         SKIPPED and recorded with its reason, never silently swallowed.
 *       - A view, trigger, routine, event or table of the dumped schema is REPLAYED.
 *         mysqldump writes each view's stand-in this way
 *         (`/*!50001 CREATE VIEW v AS SELECT 1 AS id*​/`) together with the drop in
 *         front of the final view, and the stand-ins are what let a view read a view
 *         that sorts after it.
 *       - Anything else — `DROP DATABASE`, `FLUSH`, `ANALYZE` — is skipped with a
 *         reason of its own: it does not build this schema, and a `DROP DATABASE`
 *         would reach past the shadow database.
 *     A conditional comment that only PREFIXES further SQL (a dumped view or trigger:
 *     `/*!50003 CREATE*​/ … TRIGGER … *​/`) is not a whole-statement directive and
 *     stays executable.
 *
 * ## What is replayed at all
 *
 * The replay runs on a session of the server the application's database lives on, so a statement
 * that reaches past the throwaway database reaches the real one. A dump in the
 * `mysqldump --databases` form opens with `CREATE DATABASE … app` and `USE app`, and replayed as
 * written it switched the session to the application's database and ran the dump's
 * `DROP TABLE IF EXISTS` there. So a statement is replayed only when its head, read as the server
 * reads it, is one a schema dump builds a schema with: the objects `SHOW CREATE` writes, an index,
 * `ALTER TABLE`, a drop of one of those objects, the rows and the table locks around them, a
 * session `SET`, and a transaction boundary. `USE`, anything acting on a database, a `SET` of
 * server-wide state, account and privilege statements, and everything else refuse the whole dump,
 * named by the statement's leading words and its line. So does an object named with a database in
 * front of it, `app`.`users`, which reaches the same place by another route. Laravel's own
 * `schema:dump` writes none of these.
 *
 * Three-valued throughout: a dump that cannot be split safely (an unterminated
 * literal, an unknown delimiter) is a {@see DumpFailure} carrying the line, a refused
 * statement is another, and a missing or unreadable artifact a third — never a partial
 * replay, because a half-built shadow database is green with nothing behind it.
 */
final readonly class MysqlSchemaDumpReader
{
    private const string SKIPPED_DIRECTIVE_REASON = 'MySQL version-gated client directive; session state is not replayed into the shadow database';

    private const string SKIPPED_STATEMENT_REASON = 'MySQL version-gated statement that builds no view, trigger, routine, event or table of the dumped schema; it is not replayed into the shadow database';

    /**
     * The body of a whole-statement directive that is DDL of the dumped schema: CREATE, with the
     * clauses SHOW CREATE puts before the object type, or DROP, of one of these object types.
     */
    private const string SCHEMA_OBJECT_DIRECTIVE = '/^(?:CREATE\s+(?:OR\s+REPLACE\s+)?(?:ALGORITHM\s*=\s*\w+\s+)?(?:DEFINER\s*=\s*\S+\s+)?(?:SQL\s+SECURITY\s+\w+\s+)?|DROP\s+)(?:TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT)\b/i';

    /**
     * Statement heads a schema dump builds a schema with, read once version comments are unwrapped.
     */
    private const array REPLAYABLE = [
        '/^CREATE\s+(?:OR\s+REPLACE\s+)?(?:ALGORITHM\s*=\s*\w+\s+)?(?:DEFINER\s*=\s*\S+\s+)?(?:SQL\s+SECURITY\s+\w+\s+)?(?:TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT)\b/i',
        '/^CREATE\s+(?:UNIQUE\s+|FULLTEXT\s+|SPATIAL\s+)?INDEX\b/i',
        '/^ALTER\s+TABLE\b/i',
        '/^DROP\s+(?:TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT|INDEX)\b/i',
        '/^(?:INSERT|REPLACE)\b/i',
        '/^(?:LOCK|UNLOCK)\s+TABLES\b/i',
        '/^SET\b/i',
        '/^START\s+TRANSACTION\b/i',
        '/^(?:BEGIN|COMMIT)(?:\s+WORK)?$/i',
    ];

    /**
     * Heads refused with a reason of their own, checked before the list above: each would reach
     * past the throwaway database. A `SET` of server-wide state is also a `SET`, so the order is
     * the rule.
     */
    private const array REFUSED = [
        '/^USE\b/i' => 'switches the replay to another database',
        '/^(?:CREATE|ALTER|DROP)\s+(?:DATABASE|SCHEMA)\b/i' => 'acts on a database rather than on an object of the dumped schema',
        '/^SET\s+(?:GLOBAL|PERSIST|PERSIST_ONLY)\b|@@(?:GLOBAL|PERSIST|PERSIST_ONLY)\./i' => 'changes the configuration of the whole server',
        '/^(?:GRANT|REVOKE)\b|^(?:CREATE|ALTER|DROP|RENAME)\s+(?:USER|ROLE)\b|^SET\s+(?:PASSWORD|DEFAULT\s+ROLE)\b/i' => 'changes accounts or their privileges',
    ];

    /**
     * A replayable statement whose object is named with a database in front of it, `app`.`users`:
     * it acts on that database whichever one the session is in.
     */
    private const string QUALIFIED_TARGET = '/^(?:CREATE\s+(?:OR\s+REPLACE\s+)?(?:ALGORITHM\s*=\s*\w+\s+)?(?:DEFINER\s*=\s*\S+\s+)?(?:SQL\s+SECURITY\s+\w+\s+)?(?:TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT)|ALTER\s+TABLE|DROP\s+(?:TABLE|VIEW|TRIGGER|PROCEDURE|FUNCTION|EVENT)|(?:INSERT|REPLACE)(?:\s+(?:LOW_PRIORITY|DELAYED|HIGH_PRIORITY|IGNORE))*(?:\s+INTO)?|LOCK\s+TABLES)\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?(?:`(?:[^`]|``)+`|[\w$]+)\s*\.\s*[`\w$]/i';

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
                $body = $this->directiveBody($statement);

                if (preg_match(self::SCHEMA_OBJECT_DIRECTIVE, $body) !== 1) {
                    $reason = preg_match('/^SET\b/i', $body) === 1 ? self::SKIPPED_DIRECTIVE_REASON : self::SKIPPED_STATEMENT_REASON;
                    $skipped[] = new SkippedDumpDirective($statement, $reason);

                    continue;
                }
            }

            $refusal = $this->refusal($statement);

            if ($refusal !== null) {
                return DumpFailure::refused($refusal[0], $refusal[1], $this->lineOf($dump, $statement));
            }

            $statements[] = $statement;
        }

        return new SchemaDumpPlan($statements, $skipped);
    }

    /**
     * Why a statement must not be replayed, as its leading words and the reason, or null when a
     * schema dump builds a schema with it.
     *
     * @return array{0: string, 1: string}|null
     */
    private function refusal(string $statement): ?array
    {
        $head = $this->executableText($statement);
        $form = $this->leadingKeywords($head);

        foreach (self::REFUSED as $pattern => $why) {
            if (preg_match($pattern, $head) === 1) {
                return [$form, $why];
            }
        }

        if (! array_any(self::REPLAYABLE, static fn (string $pattern): bool => preg_match($pattern, $head) === 1)) {
            return [$form, 'is not a statement a schema dump builds a schema with'];
        }

        return preg_match(self::QUALIFIED_TARGET, $head) === 1
            ? [$form, 'names an object of another database, which it would reach whichever database the replay is in']
            : null;
    }

    /**
     * The statement as the server reads it, whitespace folded: a plain block comment in front is
     * dropped, and a version-gated comment keeps its content and loses its markers, since the
     * server executes that content.
     */
    private function executableText(string $statement): string
    {
        $text = (string) preg_replace('/^\s*(?:\/\*(?!!).*?\*\/\s*)+/s', '', $statement);
        $text = str_replace('*/', ' ', (string) preg_replace('/\/\*!\d*/', ' ', $text));

        return trim((string) preg_replace('/\s+/', ' ', $text));
    }

    /**
     * The statement's first one or two words while they are bare keywords: `CREATE USER`, `USE`,
     * `SET`. A name, a literal or a password never follows into a message that reaches a log.
     */
    private function leadingKeywords(string $head): string
    {
        $words = [];

        foreach (array_slice(explode(' ', $head), 0, 2) as $word) {
            if (preg_match('/^[A-Za-z_]+$/', $word) !== 1) {
                break;
            }

            $words[] = strtoupper($word);
        }

        return $words === [] ? 'a statement' : implode(' ', $words);
    }

    /** The 1-based line a statement starts on in the dump, or null when its text cannot be found. */
    private function lineOf(string $dump, string $statement): ?int
    {
        $offset = strpos($dump, substr($statement, 0, 40));

        return $offset === false ? null : substr_count(substr($dump, 0, $offset), "\n") + 1;
    }

    /**
     * Strip leading whitespace and every leading comment MySQL skips: line comments (`-- …`,
     * `# …`), a plain block comment, and MariaDB's `/*M!… *​/`, which a MySQL server reads as a
     * plain comment as well. The MariaDB client writes one in front of every dump
     * (`/*M!999999\- enable the sandbox mode *​/`), so a dump made with it starts its first statement
     * with a comment, and a statement that is only such a comment is dropped as noise. A MySQL
     * version-gated `/*! *​/` directive is deliberately NOT stripped here: the server executes it,
     * so it is classified separately.
     */
    private function stripLeadingComments(string $statement): string
    {
        $statement = ltrim($statement);

        while ($statement !== '') {
            if (str_starts_with($statement, '--') || str_starts_with($statement, '#')) {
                $newline = strpos($statement, "\n");
                $statement = $newline === false ? '' : ltrim(substr($statement, $newline + 1));

                continue;
            }

            // A plain block comment ends at its first `*/`. The splitter refuses a dump with one that
            // never closes, so a statement that opens with one always carries its end; one without
            // would stop the stripping here, as any other text does.
            $close = str_starts_with($statement, '/*') && ! str_starts_with($statement, '/*!') ? strpos($statement, '*/', 2) : false;

            if ($close === false) {
                break;
            }

            $statement = ltrim(substr($statement, $close + 2));
        }

        return $statement;
    }

    /** What a whole-statement directive says: the text between `/*!` and its version, and `*​/`. */
    private function directiveBody(string $statement): string
    {
        $close = (int) strpos($statement, '*/', 3);

        return trim((string) preg_replace('/^\/\*!\d*/', '', substr($statement, 0, $close)));
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
