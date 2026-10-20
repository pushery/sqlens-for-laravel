<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Canonical;

/**
 * The two settings of a session's `sql_mode` that change how MySQL reads SQL text, and the
 * translation of a statement into the reading the rest of the package lexes by.
 *
 * Under `ANSI_QUOTES` a double quote delimits a name rather than a string, and under
 * `NO_BACKSLASH_ESCAPES` a backslash inside a string is an ordinary character. The binding
 * substitution, the statement splitter, the canonicalization and every rule that masks literals read
 * MySQL's default mode ({@see MysqlCanonicalization::stringLiteralDelimiters()},
 * {@see MysqlCanonicalization::usesBackslashStringEscapes()}). So a statement captured under either
 * setting is first rewritten to say the same thing in that mode: a double-quoted name becomes a
 * backtick-quoted one, and every backslash inside a string literal is doubled. Laravel's schema
 * builder writes neither form; raw SQL in a migration is written for the session it runs in.
 *
 * The settings are read from the connection's `modes`, the list Laravel sends as the session's
 * `sql_mode`. `ANSI` counts as well, because it is the combination mode that includes
 * `ANSI_QUOTES`. A connection without `modes` runs under the mode Laravel derives from `strict`, or
 * under the server's own, and neither is read here: its statements are left as they are.
 */
final readonly class MysqlSqlMode
{
    /** What may follow `--` for it to open a comment, as {@see MysqlCanonicalization::commentSyntaxes()} lists it. */
    private const string COMMENT_DASH_FOLLOWERS = " \t\n\r\v\f";

    private function __construct(
        public bool $ansiQuotes,
        public bool $noBackslashEscapes,
    ) {}

    /**
     * The settings a `database.connections.*` entry asks for.
     *
     * @param  array<array-key, mixed>  $connection
     */
    public static function ofConnection(array $connection): self
    {
        $modes = is_array($connection['modes'] ?? null) ? $connection['modes'] : [];
        $names = [];

        // Laravel joins the list with commas, so one entry may hold several modes.
        foreach ($modes as $mode) {
            if (is_string($mode)) {
                foreach (explode(',', $mode) as $name) {
                    $names[] = strtoupper(trim($name));
                }
            }
        }

        return new self(
            ansiQuotes: in_array('ANSI_QUOTES', $names, true) || in_array('ANSI', $names, true),
            noBackslashEscapes: in_array('NO_BACKSLASH_ESCAPES', $names, true),
        );
    }

    /** Whether text under these settings already reads the way the default mode reads it. */
    public function readsLikeTheDefault(): bool
    {
        return ! $this->ansiQuotes && ! $this->noBackslashEscapes;
    }

    /**
     * The statement as the default mode reads it, with the same meaning.
     *
     * Comments and backtick-quoted names are copied as they are. A literal or a name that never
     * closes is translated to the end of the text and left open, so the canonicalization still sees
     * that it never closes.
     */
    public function toDefaultReading(string $sql): string
    {
        if ($this->readsLikeTheDefault()) {
            return $sql;
        }

        $length = strlen($sql);
        $translated = '';
        $at = 0;

        while ($at < $length) {
            $char = $sql[$at];

            if ($char === "'" || ($char === '"' && ! $this->ansiQuotes)) {
                [$part, $at] = $this->literal($sql, $at, $char);
            } elseif ($char === '"') {
                [$part, $at] = $this->doubleQuotedName($sql, $at);
            } else {
                $end = $this->afterVerbatim($sql, $at);
                $part = substr($sql, $at, $end - $at);
                $at = $end;
            }

            $translated .= $part;
        }

        return $translated;
    }

    /**
     * A string literal from its opening delimiter, translated, and the offset after it.
     *
     * @return array{string, int}
     */
    private function literal(string $sql, int $at, string $delimiter): array
    {
        $length = strlen($sql);
        $part = $delimiter;
        $at++;

        while ($at < $length) {
            $char = $sql[$at];

            if ($char === $delimiter) {
                // A doubled delimiter is one delimiter of content, in every mode.
                if (($sql[$at + 1] ?? '') === $delimiter) {
                    $part .= $delimiter.$delimiter;
                    $at += 2;

                    continue;
                }

                return [$part.$delimiter, $at + 1];
            }

            if ($char === '\\' && $this->noBackslashEscapes) {
                // An ordinary character here, which the default mode writes as an escaped one.
                $part .= '\\\\';
                $at++;

                continue;
            }

            if ($char === '\\') {
                // An escape: the character after it is content, a delimiter included.
                $part .= substr($sql, $at, 2);
                $at += 2;

                continue;
            }

            $part .= $char;
            $at++;
        }

        return [$part, $at];
    }

    /**
     * A name in double quotes, rewritten into backticks, and the offset after it.
     *
     * @return array{string, int}
     */
    private function doubleQuotedName(string $sql, int $at): array
    {
        $length = strlen($sql);
        $part = '`';
        $at++;

        while ($at < $length) {
            $char = $sql[$at];

            if ($char === '"' && ($sql[$at + 1] ?? '') === '"') {
                // One double quote of the name, which a backtick-quoted name holds as it is.
                $part .= '"';
                $at += 2;

                continue;
            }

            if ($char === '"') {
                return [$part.'`', $at + 1];
            }

            // A backtick-quoted name holds a backtick doubled.
            $part .= $char === '`' ? '``' : $char;
            $at++;
        }

        return [$part, $at];
    }

    /**
     * The offset after the text that is copied as it is: a backtick-quoted name, a comment, or the
     * run of plain SQL up to the next character that opens a literal, a name or a comment.
     */
    private function afterVerbatim(string $sql, int $at): int
    {
        $length = strlen($sql);

        if ($sql[$at] === '`') {
            return $this->afterBacktickName($sql, $at);
        }

        if ($this->opensLineComment($sql, $at)) {
            $end = strpos($sql, "\n", $at);

            return $end === false ? $length : $end;
        }

        if (substr($sql, $at, 2) === '/*') {
            $end = strpos($sql, '*/', $at + 2);

            return $end === false ? $length : $end + 2;
        }

        return $at + 1;
    }

    /** The offset after a backtick-quoted name, whose only escape is a doubled backtick. */
    private function afterBacktickName(string $sql, int $at): int
    {
        $length = strlen($sql);
        $at++;

        while ($at < $length) {
            if ($sql[$at] === '`' && ($sql[$at + 1] ?? '') === '`') {
                $at += 2;

                continue;
            }

            if ($sql[$at] === '`') {
                return $at + 1;
            }

            $at++;
        }

        return $length;
    }

    /** Whether a line comment opens here: `#`, or `--` with whitespace after it. */
    private function opensLineComment(string $sql, int $at): bool
    {
        return $sql[$at] === '#'
            || (substr($sql, $at, 2) === '--' && isset($sql[$at + 2]) && str_contains(self::COMMENT_DASH_FOLLOWERS, $sql[$at + 2]));
    }
}
