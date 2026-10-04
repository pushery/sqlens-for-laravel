<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use BackedEnum;
use DateTimeInterface;
use Pushery\SQLens\Canonical\QuotedSpan;
use Pushery\SQLens\Contracts\BindingFormatter;
use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * Turns a statement plus its bindings into ONE complete SQL string for rules to
 * read.
 *
 * **This is NOT an escaper and must never be used as one.** The result is
 * analysis material and is never executed — no statement produced here reaches a
 * database. Reading it as a safe-to-run string would be a security bug, not a
 * feature request.
 *
 * The statement arrives the way PDO received it, beside its bindings: the shape
 * `DB::listen` reports. Laravel's pretend log is complete already, because the
 * framework inlines the bindings itself before it logs, and the capture decorator
 * hands it on without coming here. Two PDO conventions decide what a `?` is.
 * `??` is PDO's escape for a `?` the server receives as SQL, which is how the
 * jsonb `?`, `?|` and `?&` operators reach PostgreSQL. And a statement without
 * bindings has nothing to fill: one that ran that way went through `PDO::exec()`,
 * which sends a `?` on as SQL.
 *
 * Anything that cannot be rendered faithfully comes back as a failure with a
 * named reason. Guessing would produce a string that reads like the statement the
 * database will see and is not, which nothing downstream could detect.
 *
 * Where a literal ends is the driver's to say, in the same declaration the statement
 * splitter and the canonicalization stages read. So a MySQL value `C:\` is written
 * `'C:\\'`, and a `\'` in MySQL text does not end the literal it stands in: read
 * or written any other way, this class and the splitter would disagree about where
 * a statement goes on.
 */
final readonly class BindingSubstitutor
{
    public function __construct(
        private BindingFormatter $formatter,
        private DriverCanonicalization $syntax,
    ) {}

    /**
     * @param  list<mixed>  $bindings
     */
    public function substitute(string $sql, array $bindings): string|SubstitutionFailure
    {
        $marks = $this->questionMarks($sql);
        $positions = array_keys(array_filter($marks, static fn (bool $escaped): bool => ! $escaped));

        // Bindings with no placeholder to fill are named ones (`:id`), or a text that
        // carries its values already, and neither is substituted here. Without
        // bindings, every `?` is SQL.
        $fill = $positions !== [] && $bindings !== [];

        if ($fill && count($positions) !== count($bindings)) {
            return SubstitutionFailure::countMismatch(count($positions), count($bindings));
        }

        $out = '';
        $cursor = 0;
        $index = 0;

        foreach ($marks as $offset => $escaped) {
            if ($escaped) {
                // PDO's escape: the server receives one `?`.
                $out .= substr($sql, $cursor, $offset - $cursor).'?';
                $cursor = $offset + 2;

                continue;
            }

            if (! $fill) {
                continue;
            }

            $literal = $this->literalFor($bindings[$index], $index + 1);

            if ($literal instanceof SubstitutionFailure) {
                return $literal;
            }

            $out .= substr($sql, $cursor, $offset - $cursor).$literal;
            $cursor = $offset + 1;
            $index++;
        }

        return $out.substr($sql, $cursor);
    }

    /**
     * Every `?` outside a literal, by offset: true where it opens PDO's `??` escape,
     * false where it is a placeholder.
     *
     * A `?` inside a string literal or a quoted identifier is DATA, not a placeholder.
     * Substituting it would corrupt the statement in a way that still parses — the
     * worst kind of wrong, because nothing downstream would flag it.
     *
     * A literal ends where the driver's syntax ends it, a MySQL backslash escape
     * included: Laravel writes a MySQL column comment through `addslashes()`, so
     * `'What\'s this?'` is one literal there and the `?` in it is text.
     *
     * @return array<int, bool>
     */
    private function questionMarks(string $sql): array
    {
        $marks = [];
        $length = strlen($sql);
        $delimiters = $this->syntax->stringLiteralDelimiters();
        $identifierQuote = $this->syntax->quotingCharacter();
        $backslashEscapes = $this->syntax->usesBackslashStringEscapes();
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];

            // An unterminated literal or identifier quotes the rest, so a stray `?`
            // after it is not mistaken for a placeholder.
            if (in_array($char, $delimiters, true)) {
                $i = QuotedSpan::endOfLiteral($sql, $i, $char, $backslashEscapes) ?? $length;

                continue;
            }

            if ($char === $identifierQuote) {
                $i = QuotedSpan::endOfQuotedIdentifier($sql, $i, $char) ?? $length;

                continue;
            }

            if ($char === '?') {
                // `??` is two characters and one mark.
                $marks[$i] = ($sql[$i + 1] ?? '') === '?';
                $i += $marks[$i] ? 2 : 1;

                continue;
            }

            $i++;
        }

        return $marks;
    }

    /** The SQL literal for one binding, or a named failure. */
    private function literalFor(mixed $value, int $position): string|SubstitutionFailure
    {
        if ($value instanceof BackedEnum) {
            $value = $value->value;
        }

        return match (true) {
            $value === null => 'NULL',
            is_bool($value) => $this->formatter->booleanLiteral($value),
            is_int($value) => (string) $value,
            is_float($value) => $this->floatLiteral($value, $position),
            $value instanceof DateTimeInterface => $this->quote($value->format($this->formatter->dateFormat())),
            is_string($value) => $this->stringLiteral($value),
            default => SubstitutionFailure::unrepresentable(get_debug_type($value), $position),
        };
    }

    /**
     * A float, rendered locale-independently and still recognizably a float.
     *
     * JSON number formatting is locale-independent by specification, so a machine
     * with a comma decimal separator produces byte-identical output — and a comma
     * would be worse than ugly here: `1,5` parses as TWO values in an argument
     * list, so the corrupted statement would still look plausible.
     *
     * A whole float encodes as `1`, which would read as an integer. The decimal
     * point is restored so a rule can still tell a float literal from an int one.
     */
    private function floatLiteral(float $value, int $position): string|SubstitutionFailure
    {
        if (! is_finite($value)) {
            return SubstitutionFailure::unrepresentable('non-finite float', $position);
        }

        $encoded = json_encode($value, JSON_THROW_ON_ERROR);

        return str_contains($encoded, '.') || str_contains($encoded, 'e') || str_contains($encoded, 'E')
            ? $encoded
            : $encoded.'.0';
    }

    /**
     * A string binding. A byte string that is not text, invalid UTF-8 or holding a
     * NUL, is written as the engine's hex literal of the same bytes: raw bytes in
     * the analysis text would corrupt the canonical form and could not survive a
     * JSON report, and a binary UUID is an ordinary value to insert.
     */
    private function stringLiteral(string $value): string
    {
        if (! mb_check_encoding($value, 'UTF-8') || str_contains($value, "\0")) {
            return $this->formatter->binaryLiteral($value);
        }

        return $this->quote($value);
    }

    /**
     * Single-quoted with doubled quotes — the form every supported engine reads. A
     * driver that reads a backslash as an escape, as MySQL does by default, gets the
     * backslash doubled too: `C:\` written as it is would end in `\'`, a literal that
     * never closes.
     */
    private function quote(string $value): string
    {
        $doubled = str_replace("'", "''", $value);

        return "'".($this->syntax->usesBackslashStringEscapes() ? str_replace('\\', '\\\\', $doubled) : $doubled)."'";
    }
}
