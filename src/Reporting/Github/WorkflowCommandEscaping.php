<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Github;

use Pushery\SQLens\Console\FormatCommand;

/**
 * The two escapes a GitHub workflow command needs, in one place because two suites emit them.
 *
 * The rule is not cosmetic. A workflow command is ONE line, terminated by the newline; an
 * unescaped `\n` in a message does not produce a two-line annotation, it produces one annotation
 * that ends early and a second line GitHub reads as ordinary log output. So the half of the message
 * that mattered — the reason a file could not be formatted, say — is silently dropped from the
 * annotation and appears nowhere a reviewer looks.
 *
 * It lives here rather than in each emitter because the escapes are a property of the WIRE FORMAT,
 * not of what is being reported. {@see GithubReporter} renders findings and
 * {@see FormatCommand} renders file outcomes; they share no result model at
 * all, and duplicating two `str_replace` calls across them is how one of the two ends up missing a
 * character the other learned about.
 */
final class WorkflowCommandEscaping
{
    /** Escape a workflow-command MESSAGE: `%` first so later replacements are not re-escaped. */
    public static function data(string $value): string
    {
        return str_replace(['%', "\r", "\n"], ['%25', '%0D', '%0A'], $value);
    }

    /** Escape a workflow-command PROPERTY value: the message escapes plus `:` and `,`. */
    public static function property(string $value): string
    {
        return str_replace(['%', "\r", "\n", ':', ','], ['%25', '%0D', '%0A', '%3A', '%2C'], $value);
    }
}
