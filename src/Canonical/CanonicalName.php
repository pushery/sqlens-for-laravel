<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * One name as a PostgreSQL canonical statement writes it, for a reader that has to find it in the text.
 *
 * The canonical form leaves a name unquoted where the server reads it back the same, and quotes it
 * otherwise: `"Email"`, `"2fa_enabled"`, `"first name"`, with a quote inside doubled. Unquoted it is
 * a run of anything but a space, a quote, a parenthesis, a comma or a semicolon, because PostgreSQL
 * takes letters beyond ASCII there: `élan` is one name. A pattern that allowed only `[a-z0-9_]`
 * did not see those columns at all, and a rule reading nothing reports nothing.
 */
final class CanonicalName
{
    /** One name, to be placed inside a larger pattern. It captures nothing of its own. */
    public const string PATTERN = '"(?:[^"]|"")+"|[^\s"(),;]+';

    /** The name without its quoting, with a doubled quote read as one. */
    public static function bare(string $name): string
    {
        return strlen($name) >= 2 && str_starts_with($name, '"') && str_ends_with($name, '"')
            ? str_replace('""', '"', substr($name, 1, -1))
            : $name;
    }
}
