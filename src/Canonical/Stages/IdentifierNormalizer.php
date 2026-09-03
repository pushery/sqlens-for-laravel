<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\Identifier;
use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Collapses the quoting of identifier references so `"users"`, `users` and (under
 * MySQL) `` `users` `` are the same to a rule, and folds their case per the driver
 * — the precondition for a later drift comparison that is not just quoting noise.
 *
 * What it does NOT do is normalize qualification: `public."users"` becomes
 * `public.users` (each part canonicalized), never `users`. Collapsing the schema
 * away would silently assume a `search_path`, which the audit suite decides by
 * configuration, not this layer. The schema stays a separate, comparable part.
 *
 * Scope is deliberately the positions it can identify with certainty from the
 * grammar output: quoted identifiers and dot-qualified chains — which is exactly
 * what the schema grammar emits (it quotes every identifier). A STANDALONE bare
 * word is left untouched: telling a bare identifier from a keyword needs the
 * keyword list and is the keyword-casing stage's concern; a bare identifier's
 * folding is carried by the Identifier value object, exercised directly. Whitespace
 * inside a string literal, dollar-quoted body, comment or the identifier itself is
 * never mistaken for an identifier position.
 *
 * Three-valued: an unterminated or malformed quote, an over-qualified reference
 * (`a.b.c`), or a driver with no identifier quote abort with a named
 * CanonicalizationFailure that the pipeline propagates — never a silent, wrong
 * rewrite. The literal/comment/dollar-quote scanning mirrors the sibling stages; a
 * shared lexer is a later refactor kept out to keep each stage independently
 * correct.
 */
final readonly class IdentifierNormalizer implements CanonicalizationStage
{
    public function __construct(private DriverCanonicalization $driver) {}

    public function __invoke(RawStatement $statement, SubjectContext $context): mixed
    {
        $result = $this->normalize($statement->sql);

        return $result instanceof CanonicalizationFailure
            ? $result
            : $statement->withSql($result);
    }

    private function normalize(string $sql): string|CanonicalizationFailure
    {
        $quote = $this->driver->quotingCharacter();
        if ($quote === '') {
            return CanonicalizationFailure::missingCanonicalArtifact('identifier quoting character');
        }

        $literals = $this->driver->stringLiteralDelimiters();
        $commentMarkers = $this->driver->commentSyntaxes();
        $lineComments = array_values(array_filter($commentMarkers, static fn (string $marker): bool => $marker !== '/*'));
        $hasBlockComment = in_array('/*', $commentMarkers, true);

        $out = '';
        $length = strlen($sql);
        $i = 0;

        while ($i < $length) {
            $char = $sql[$i];
            $rest = substr($sql, $i);

            if ($this->matchPrefix($rest, $lineComments) !== null) {
                $newline = strpos($sql, "\n", $i);
                $end = $newline === false ? $length : $newline;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($hasBlockComment && str_starts_with($rest, '/*')) {
                $close = strpos($sql, '*/', $i + 2);
                $end = $close === false ? $length : $close + 2;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($this->driver->supportsDollarQuotedStrings() && $char === '$' && preg_match('/\A\$\w*\$/', $rest, $matches) === 1) {
                $tag = $matches[0];
                $close = strpos($sql, $tag, $i + strlen($tag));
                $end = $close === false ? $length : $close + strlen($tag);
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            $literal = $this->matchPrefix($rest, $literals);
            if ($literal !== null) {
                $end = $this->scanQuoted($sql, $i, $literal) ?? $length;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            // A quoted identifier, or a bare word that qualifies the part after a dot.
            if ($char === $quote || $this->startsQualifiedChain($sql, $i, $quote)) {
                $end = $this->chainExtent($sql, $i, $quote);
                $identifier = Identifier::parse(substr($sql, $i, $end - $i), $this->driver);
                if ($identifier instanceof CanonicalizationFailure) {
                    return $identifier;
                }

                $out .= $identifier->canonical();
                $i = $end;

                continue;
            }

            // A standalone bare word: copied verbatim (see the class docblock).
            if ($this->isBareStart($char)) {
                $end = $this->bareWordEnd($sql, $i);
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            $out .= $char;
            $i++;
        }

        return $out;
    }

    /**
     * Whether the bare word starting at $i is a schema qualifier — followed
     * immediately by a dot and then another identifier part.
     */
    private function startsQualifiedChain(string $sql, int $i, string $quote): bool
    {
        if (! $this->isBareStart($sql[$i])) {
            return false;
        }

        $end = $this->bareWordEnd($sql, $i);

        return $end + 1 < strlen($sql)
            && $sql[$end] === '.'
            && $this->isPartStart($sql[$end + 1], $quote);
    }

    /** The index just past a maximal `part('.'part)*` identifier chain starting at $start. */
    private function chainExtent(string $sql, int $start, string $quote): int
    {
        $length = strlen($sql);
        $j = $start;

        while (true) {
            if ($sql[$j] === $quote) {
                $close = $this->scanQuoted($sql, $j, $quote);
                if ($close === null) {
                    return $length; // unterminated — Identifier::parse names the failure
                }

                $j = $close;
            } else {
                $j = $this->bareWordEnd($sql, $j);
            }

            if ($j < $length && $sql[$j] === '.' && $j + 1 < $length && $this->isPartStart($sql[$j + 1], $quote)) {
                $j++;

                continue;
            }

            return $j;
        }
    }

    private function isPartStart(string $char, string $quote): bool
    {
        return $char === $quote || $this->isBareStart($char);
    }

    private function isBareStart(string $char): bool
    {
        return preg_match('/[A-Za-z_\x80-\xff]/', $char) === 1;
    }

    private function bareWordEnd(string $sql, int $start): int
    {
        $length = strlen($sql);
        $j = $start;

        while ($j < $length && preg_match('/[A-Za-z0-9_$\x80-\xff]/', $sql[$j]) === 1) {
            $j++;
        }

        return $j;
    }

    /**
     * @param  list<string>  $candidates
     */
    private function matchPrefix(string $haystack, array $candidates): ?string
    {
        foreach ($candidates as $candidate) {
            if ($candidate !== '' && str_starts_with($haystack, $candidate)) {
                return $candidate;
            }
        }

        return null;
    }

    private function scanQuoted(string $sql, int $start, string $quote): ?int
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

        return null;
    }
}
