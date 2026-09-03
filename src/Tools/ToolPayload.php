<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

use Pushery\SQLens\Canonical\CanonicalStatement;

/**
 * The handover form: one SQL document built from the canonical statements, plus the line span
 * each statement occupies in it.
 *
 * A tool answers in line numbers against the text it was given, and that text is not a file
 * anyone has — it is assembled here. Without the spans, a finding at line 7 is a fact about a
 * string that exists for the length of one subprocess. The spans are what turn it back into
 * "the third statement of this migration", and they are recorded WHILE the document is built
 * rather than reconstructed afterwards by counting semicolons: a second parse of the same text
 * is a second chance to disagree with the first.
 *
 * Tool-NEUTRAL, and it lives here rather than beside the Squawk adapter for that reason. Handing
 * a document to a program and getting positions back is what every one of them does; a per-tool
 * copy of this would be four chances to count lines differently.
 *
 * The canonical form is what goes over, never the raw grammar output. Raw text carries the
 * framework's formatting of the day, so findings would move under a Laravel upgrade that
 * changed nothing about the migration.
 */
final readonly class ToolPayload
{
    /**
     * The general form. {@see self::of()} is how a payload is normally built; this constructor
     * exists because the mapper must not assume the spans are contiguous — a document assembled
     * differently is a payload too, and a mapper that only worked on this builder's output would
     * be tested against its own assumption.
     *
     * @param  list<CanonicalStatement>  $statements
     * @param  list<ToolStatementSpan>  $spans
     */
    public function __construct(
        /** The document handed to the tool on standard input. */
        public string $sql,
        /**
         * The statements the document was built from, in capture order.
         *
         * They travel WITH the spans rather than beside them, because a span is a number without
         * them and the two coming from different builds is the one mistake that cannot be caught
         * afterwards — every finding would map cleanly, to the wrong statement.
         */
        public array $statements,
        /**
         * One span per statement, in the order they appear.
         *
         * @var list<ToolStatementSpan>
         */
        public array $spans,
    ) {}

    /**
     * Build the document. Statement order is preserved, because it is the only thing tying a
     * finding back to a statement: nothing in the text identifies which statement it came from.
     *
     * Every statement gets its terminator back (the splitter took it off) and its own line,
     * which is what keeps the spans meaningful. A statement can still span several lines — a
     * multi-line string literal survives canonicalization byte-exact — so the span is counted
     * from the text rather than assumed to be one line each.
     *
     * @param  list<CanonicalStatement>  $statements
     */
    public static function of(array $statements): self
    {
        $sql = '';
        $spans = [];
        $line = 1;

        foreach ($statements as $index => $statement) {
            $text = rtrim($statement->canonicalSql);
            $text = str_ends_with($text, ';') ? $text : $text.';';

            $height = substr_count($text, "\n") + 1;
            $spans[] = new ToolStatementSpan($index, $line, $line + $height - 1);

            $sql .= $text."\n";
            $line += $height;
        }

        return new self($sql, $statements, $spans);
    }
}
