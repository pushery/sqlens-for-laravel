<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

/**
 * Fills a template's placeholders with each value written for the place it stands in.
 *
 * A value is text a finding measured: an enum label out of a migration, a table or collation name
 * out of the catalog. Some templates put one inside a quoted literal, and a value that carries the
 * quote ends that literal early. `ALTER TYPE feedback ADD VALUE IF NOT EXISTS '{{value}}'` filled
 * with the label `don't_know` was SQL no server accepts, and filled with `x'; DROP TABLE users; --`
 * it was two statements, the second of which runs for whoever applies the material.
 *
 * So the fill reads the syntax of the template, never of the value. In SQL a placeholder inside a
 * single-quoted literal gets each quote doubled. In a Laravel snippet a placeholder inside a PHP
 * string gets the escapes that string needs. Everywhere else a value goes in as it is, which is what
 * the templates put there: identifiers `Identifier::canonical()` has already quoted, SQL fragments and
 * numbers.
 */
final class PlaceholderFill
{
    /** A placeholder in the grammar the remediation validator holds every template to. */
    private const string PLACEHOLDER = '/\{\{[a-z][a-z0-9_]*\}\}/';

    /** The pieces of an SQL template: its placeholders, its quotes, and the text between them. */
    private const string SQL_PIECES = "/(\\{\\{[a-z][a-z0-9_]*\\}\\}|')/";

    /**
     * Fill an SQL template.
     *
     * A quote in a template opens or closes a literal, and a doubled one does both: the templates
     * carry no comment, no dollar quoting and no double-quoted identifier around a quote. A value with
     * a backslash leaves its placeholder standing when it would land inside a literal. MySQL reads a
     * backslash there as an escape, and so does PostgreSQL once `standard_conforming_strings` is off,
     * so no one spelling of the value means the same on every server, and the reader fills it in.
     *
     * @param  array<string, string>  $context  placeholder name => value, without the braces
     */
    public static function sql(string $template, array $context): string
    {
        $filled = '';
        $inLiteral = false;

        foreach (preg_split(self::SQL_PIECES, $template, -1, PREG_SPLIT_DELIM_CAPTURE) ?: [$template] as $piece) {
            $inLiteral = $piece === "'" ? ! $inLiteral : $inLiteral;
            $value = str_starts_with($piece, '{{') ? ($context[substr($piece, 2, -2)] ?? null) : null;

            $filled .= match (true) {
                $value === null, $inLiteral && str_contains($value, '\\') => $piece,
                $inLiteral => str_replace("'", "''", $value),
                default => $value,
            };
        }

        return $filled;
    }

    /**
     * Fill a Laravel snippet.
     *
     * Read as the PHP it is: each placeholder is first swapped for one name-shaped token, so that a
     * placeholder in code stays one token and one inside a string stays that string's text, and the
     * snippet is then tokenized. A value that lands in a single-quoted string gets its backslashes and
     * quotes escaped, one in a double-quoted string its backslashes, quotes and dollar signs.
     *
     * @param  array<string, string>  $context  placeholder name => value, without the braces
     */
    public static function php(string $snippet, array $context): string
    {
        $values = [];

        $marked = preg_replace_callback(self::PLACEHOLDER, static function (array $match) use ($context, &$values): string {
            $name = substr($match[0], 2, -2);

            if (! array_key_exists($name, $context)) {
                return $match[0];
            }

            $marker = '__sqlens_placeholder_'.count($values).'__';
            $values[$marker] = $context[$name];

            return $marker;
        }, $snippet) ?? $snippet;

        $filled = '';

        foreach (array_slice(token_get_all('<?php '.$marked), 1) as $token) {
            [$kind, $text] = is_array($token) ? $token : [null, $token];

            $escape = match (true) {
                $kind === T_CONSTANT_ENCAPSED_STRING && $text[0] === "'" => "\\'",
                $kind === T_CONSTANT_ENCAPSED_STRING, $kind === T_ENCAPSED_AND_WHITESPACE => '\\"$',
                default => '',
            };

            $filled .= strtr($text, array_map(static fn (string $value): string => addcslashes($value, $escape), $values));
        }

        return $filled;
    }
}
