<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use Illuminate\Console\OutputStyle;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes report text exactly as it was produced, with its control characters made visible.
 *
 * A report carries text somebody else wrote: migration SQL, catalog names, file paths, a tool's
 * output. Two readers act on that text on its way out, and neither may.
 *
 * The console formatter reads `<info>…</info>` as a style and `\<` as an escaped bracket. A table
 * named `<info>legacy</info>` would be reported as `legacy`, which names another object, and a CHECK
 * regex holding `\<` would leave a JSON report with an escape no parser accepts. So every line is
 * written raw. The reports set no style of their own, so raw output is their text without that
 * reading.
 *
 * A terminal, and a CI log viewer, reads control characters. ESC starts a sequence that can move the
 * cursor or erase a line, and a carriage return goes back to the start of one, so a finding could
 * overwrite the line that reports it. Each is written as a visible escape instead: `\x1B` for ESC,
 * `\u009B` for its one-byte form. Tab and newline stay, because the reports lay out their own text
 * with them.
 */
final class ReportText
{
    /** One line or block of a report that a person, a log or an agent reads. */
    public static function line(OutputInterface $out, string $text): void
    {
        $out->writeln(self::visible($text), OutputInterface::OUTPUT_RAW);
    }

    /**
     * A machine document, whose own encoding already escapes every control character.
     *
     * Written below Laravel's console style when one is in front. A style can rewrite what passes
     * through it, raw or not, and an agent's console often has one that does: laravel/pao cleans
     * every message for the agent reading it, which collapses the spaces inside an SQL string,
     * drops an arrow and shortens `...`. The document stays valid JSON and stops being the one the
     * run produced.
     */
    public static function document(OutputInterface $out, string $document): void
    {
        ($out instanceof OutputStyle ? $out->getOutput() : $out)->writeln($document, OutputInterface::OUTPUT_RAW);
    }

    /** The text with every control character except tab and newline written as a visible escape. */
    public static function visible(string $text): string
    {
        // Byte-wise, without `u`: a C1 control is the two bytes `\xC2\x80` to `\xC2\x9F`, and a byte
        // in that range after any other lead byte belongs to an ordinary character. The pattern has
        // no quantifier, so it cannot run into the backtracking limit that makes `preg_*` fail.
        return preg_replace_callback(
            '/[\x00-\x08\x0B-\x1F\x7F]|\xC2[\x80-\x9F]/',
            static fn (array $match): string => strlen($match[0]) === 1
                ? sprintf('\x%02X', ord($match[0]))
                : sprintf('\u%04X', ord($match[0][1])),
            $text,
        ) ?? $text;
    }
}
