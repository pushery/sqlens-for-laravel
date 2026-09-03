<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Squawk;

/**
 * One entry of the tool's JSON report, read strictly and not yet interpreted.
 *
 * Deliberately a separate shape from a SQLens finding. Mapping the two is its own step with its
 * own rules; conflating them here would mean the reader of a rule id could no longer tell
 * whether it came from us or from a tool, and a tool's vocabulary would leak into ours.
 *
 * "Strictly" means a shape this does not recognize becomes a named undetermined rather than a
 * partially-filled object. Unknown FIELDS are ignored — a tool is allowed to add one — but a
 * missing required field is not filled in with a default: a default here is a claim about the
 * finding's position or severity that nobody made.
 */
final readonly class SquawkRawFinding
{
    /** The value the tool uses for a statement it could not parse — not a rule, a parse failure. */
    public const string SYNTAX_ERROR_RULE = 'syntax-error';

    public function __construct(
        /** The path the tool reported, which is the one we told it to report via `--stdin-filepath`. */
        public string $file,
        /**
         * ZERO-based, and the name says so because the tool's are.
         *
         * Measured against a three-line document: a finding on the third line comes back as
         * `line: 2`. Nothing downstream may use this number as a line number without adding one,
         * and a property called `line` would have invited exactly that.
         */
        public int $zeroBasedLine,
        public int $zeroBasedColumn,
        public int $zeroBasedLineEnd,
        public int $zeroBasedColumnEnd,
        /** The tool's own severity word, e.g. `Warning` or `Error` — mapped later, never here. */
        public string $level,
        public string $message,
        /** The tool's own rule name, e.g. `require-concurrent-index-creation`. */
        public string $ruleName,
        /** The tool's suggested fix, when it offers one. */
        public ?string $help = null,
    ) {}

    /**
     * Read one report entry, or null when it is not the shape this adapter was written against.
     *
     * Null rather than an exception: an unreadable report is a fact about the run, and the
     * caller turns it into a named undetermined. A throw here would make an optional amplifier
     * able to end the lint run that merely asked it a question.
     */
    public static function fromReportEntry(mixed $entry): ?self
    {
        if (! is_array($entry)) {
            return null;
        }

        foreach (['file' => 'is_string', 'level' => 'is_string', 'message' => 'is_string', 'rule_name' => 'is_string',
            'line' => 'is_int', 'column' => 'is_int', 'line_end' => 'is_int', 'column_end' => 'is_int'] as $key => $check) {
            if (! array_key_exists($key, $entry) || ! $check($entry[$key])) {
                return null;
            }
        }

        // `help` is genuinely optional: the tool sends null for rules that suggest nothing, and a
        // missing key would say the same thing. It carries no position and no severity, so
        // treating its absence as an unreadable report would reject a perfectly usable finding.
        $help = $entry['help'] ?? null;

        return new self(
            file: $entry['file'],
            zeroBasedLine: $entry['line'],
            zeroBasedColumn: $entry['column'],
            zeroBasedLineEnd: $entry['line_end'],
            zeroBasedColumnEnd: $entry['column_end'],
            level: $entry['level'],
            message: $entry['message'],
            ruleName: $entry['rule_name'],
            help: is_string($help) ? $help : null,
        );
    }

    /**
     * Whether this entry is the tool saying it could not parse the SQL.
     *
     * It arrives as an ordinary finding — measured: same array, same exit code, `rule_name` set
     * to `syntax-error`. Nothing about the transport distinguishes it, so a caller that only
     * looked at exit codes would file a parse failure as a lint result and report the analysis
     * as complete when it never happened.
     */
    public function isSyntaxError(): bool
    {
        return $this->ruleName === self::SYNTAX_ERROR_RULE;
    }
}
