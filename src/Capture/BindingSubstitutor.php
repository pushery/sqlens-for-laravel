<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use BackedEnum;
use DateTimeInterface;
use Pushery\SQLens\Contracts\BindingFormatter;

/**
 * Turns a statement plus its bindings into ONE complete SQL string for rules to
 * read.
 *
 * **This is NOT an escaper and must never be used as one.** The result is
 * analysis material and is never executed — no statement produced here reaches a
 * database. Reading it as a safe-to-run string would be a security bug, not a
 * feature request.
 *
 * The two capture modes hand over different shapes: Laravel's pretend log already
 * inlines bindings into the query text, while `DB::listen` reports the statement
 * and its bindings separately. Normalizing that difference is this class's real
 * job — an already-complete statement passes through untouched, and only a
 * statement that still carries placeholders is substituted.
 *
 * Anything that cannot be rendered faithfully comes back as a failure with a
 * named reason. Guessing would produce a string that reads like the statement the
 * database will see and is not, which nothing downstream could detect.
 */
final readonly class BindingSubstitutor
{
    public function __construct(private BindingFormatter $formatter) {}

    /**
     * @param  list<mixed>  $bindings
     */
    public function substitute(string $sql, array $bindings): string|SubstitutionFailure
    {
        $positions = $this->placeholderPositions($sql);

        // The pretend log arrives already inlined: no placeholders left, and the
        // bindings are informational. That is a complete statement, not a mismatch.
        if ($positions === [] && $bindings !== []) {
            return $sql;
        }

        if (count($positions) !== count($bindings)) {
            return SubstitutionFailure::countMismatch(count($positions), count($bindings));
        }

        $out = '';
        $cursor = 0;

        foreach ($positions as $index => $position) {
            $literal = $this->literalFor($bindings[$index], $index + 1);

            if ($literal instanceof SubstitutionFailure) {
                return $literal;
            }

            $out .= substr($sql, $cursor, $position - $cursor).$literal;
            $cursor = $position + 1;
        }

        return $out.substr($sql, $cursor);
    }

    /**
     * The offsets of the real placeholders.
     *
     * A `?` inside a string literal is DATA, not a placeholder. Substituting it
     * would corrupt the statement in a way that still parses — the worst kind of
     * wrong, because nothing downstream would flag it.
     *
     * @return list<int>
     */
    private function placeholderPositions(string $sql): array
    {
        $positions = [];
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];

            if (in_array($char, ["'", '"', '`'], true)) {
                $i = $this->skipQuoted($sql, $i, $char);

                continue;
            }

            if ($char === '?') {
                $positions[] = $i;
            }

            $i++;
        }

        return $positions;
    }

    /** The index just past a quoted run, honoring doubled quotes as escapes. */
    private function skipQuoted(string $sql, int $start, string $quote): int
    {
        $length = strlen($sql);
        $j = $start + 1;

        while ($j < $length) {
            if ($sql[$j] === $quote) {
                if ($j + 1 < $length && $sql[$j + 1] === $quote) {
                    $j += 2;

                    continue;
                }

                return $j + 1;
            }

            $j++;
        }

        // Unterminated: treat the rest as quoted, so a stray `?` after it is not
        // mistaken for a placeholder.
        return $length;
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
            is_string($value) => $this->stringLiteral($value, $position),
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
     * A string binding. Binary data is marked rather than inlined: raw bytes in
     * the analysis text would corrupt the canonical form and could not survive a
     * JSON report anyway, and a rule has no use for the bytes themselves.
     */
    private function stringLiteral(string $value, int $position): string|SubstitutionFailure
    {
        if (! mb_check_encoding($value, 'UTF-8')) {
            return SubstitutionFailure::unrepresentable('binary string', $position);
        }

        return $this->quote($value);
    }

    /** Single-quoted with doubled quotes — the form every supported engine reads. */
    private function quote(string $value): string
    {
        return "'".str_replace("'", "''", $value)."'";
    }
}
