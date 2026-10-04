<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Agent;

use Pushery\SQLens\Reporting\ReportText;

/**
 * Text somebody else wrote, made safe to stand inside the agent report's markdown.
 *
 * The agent report is the one format whose STRUCTURE is the instruction: a heading says what kind
 * of thing follows, and a list item under "What to fix" says what to do. A finding's message, the
 * name of a catalog object and a tool's own rule id are text this package did not write, and
 * markdown has no field to keep them in. A line break in any of them starts a new block, so a table
 * named `x`, a line break and `## What to fix` would write a heading of its own into the document an
 * agent acts on.
 *
 * So a line break inside such a field is written as the visible escape {@see ReportText}
 * already uses for every other control character (`\x0A`, `\x0D`), and a fenced block is fenced with
 * more backticks than its content holds in a row, so no line of the content can close it.
 */
final class MarkdownText
{
    /** The text as it may stand inside one line of the report: every line break made visible. */
    public static function inline(string $text): string
    {
        return strtr($text, ["\r" => '\x0D', "\n" => '\x0A']);
    }

    /**
     * A code fence the given content cannot close: one backtick longer than the longest run of
     * backticks in it, and never shorter than the three a fence needs.
     */
    public static function fence(string $content): string
    {
        $longest = 0;

        if (preg_match_all('/`+/', $content, $runs) > 0) {
            foreach ($runs[0] as $run) {
                $longest = max($longest, strlen($run));
            }
        }

        return str_repeat('`', max(3, $longest + 1));
    }
}
