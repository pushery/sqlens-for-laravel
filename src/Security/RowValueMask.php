<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

/**
 * A row value taken out of a database error message, found by the SHAPE of the message.
 *
 * A constraint the database enforces quotes the row it refused. PostgreSQL writes
 * `Key (email)=(alice@example.com) already exists.` and, for a not-null or check violation,
 * `Failing row contains (3, alice@example.com, …)`, every column of the row; MySQL writes
 * `Duplicate entry 'alice@example.com' for key 'users.email'`. A capture failure carries that message
 * into the finding, so a migration inserting a value it read from the environment, an administrator's
 * address or a password hash, printed the value into the CI log, the JSON report and SARIF alike.
 *
 * ## The value goes, the sentence stays
 *
 * Each shape keeps everything around the value: the column list, the constraint, the key. That is
 * what a reader needs to find the failing statement, and none of it is row data. The value is
 * replaced by the same placeholder {@see SecretLiteralMask} uses, so a reader sees that something was
 * there.
 *
 * ## By shape, and only the shapes measured
 *
 * The patterns are the messages PostgreSQL 18 and MySQL 8.4 were measured writing. A message in
 * another shape passes unchanged rather than being guessed at; masking every quoted string instead
 * would take the identifiers too, and those are what makes the message useful. The statement excerpt
 * PostgreSQL appends (`LINE 1: …`) is the SQL the migration sent and is left as it is: it quotes a
 * value only where the migration wrote the value into its own SQL. A statement with bound values, as
 * Laravel's query builder sends one, gets no excerpt: PostgreSQL names the parameter instead and
 * prints its value as `'...'` itself.
 */
final readonly class RowValueMask
{
    /**
     * Each pattern captures the text before the value, the value, and the text after it.
     *
     * @var list<string>
     */
    private const array VALUE_PATTERNS = [
        // PostgreSQL, unique and foreign-key violations: `Key (email)=(…) already exists.`. A column
        // list keeps its names and may hold one level of parentheses, as an expression index does
        // with `lower(email)`. The value runs to the parenthesis before the words that end the
        // sentence, so a value holding a parenthesis is masked whole.
        '/(\bKey \((?:[^()]|\([^()]*\))*\)=\()(.*?)(\) (?:already exists|is not present in table|is still referenced from table|conflicts with existing key))/',
        // PostgreSQL, the second key of an exclusion violation: `… existing key (period)=(…).`.
        '/(\bexisting key \((?:[^()]|\([^()]*\))*\)=\()(.*)(\)\.)$/m',
        // PostgreSQL, not-null and check violations: `Failing row contains (…).`.
        '/(\bFailing row contains \()(.*)(\)\.?)$/m',
        // PostgreSQL, a row no partition accepts: `Partition key of the failing row contains (region) = (…).`.
        '/(\bPartition key of the failing row contains \((?:[^()]|\([^()]*\))*\) = \()(.*)(\)\.?)$/m',
        // PostgreSQL, a value its type refused, quoted at the end of the line:
        // `invalid input syntax for type integer: "…"`, and every refusal written the same way.
        '/(:\s")((?:[^"]|"")*)("\s*)$/m',
        // PostgreSQL: `value "…" is out of range for type integer`.
        '/(\bvalue ")((?:[^"]|"")*)(" is out of range for type\b)/',
        // PostgreSQL, a JSON value that does not parse: `Token "…" is invalid.`, and the context line
        // after it, which quotes the document from the failing line on: `JSON data, line 1: …`.
        '/(\bToken ")((?:[^"]|"")*)(" is invalid\b)/',
        '/(\bJSON data, line \d+: )(.*)()$/m',
        // MySQL: `Duplicate entry '…' for key 'users.email'`. The value is printed unescaped, so it
        // runs to the last ` for key '` on the line rather than to the next quote.
        "/(\\bDuplicate entry ')(.*)(' for key ')/",
        // MySQL: `Incorrect integer value: '…' for column 'id' at row 1`.
        "/(\\bIncorrect \\w+ value: ')(.*)(' for column ')/",
        // MySQL: `Truncated incorrect DOUBLE value: '…'`.
        "/(\\bTruncated incorrect \\w+ value: ')(.*)(')$/m",
    ];

    /** The message with every row value it quotes replaced, and everything else untouched. */
    public static function in(string $message): string
    {
        $masked = $message;

        foreach (self::VALUE_PATTERNS as $pattern) {
            // A pattern that fails to run leaves the text as it was rather than emptying it, as in
            // SecretLiteralMask: a null here would turn the message into nothing at all.
            $masked = preg_replace_callback(
                $pattern,
                static fn (array $match): string => $match[1].SecretLiteralMask::PLACEHOLDER.$match[3],
                $masked,
            ) ?? $masked;
        }

        return $masked;
    }
}
