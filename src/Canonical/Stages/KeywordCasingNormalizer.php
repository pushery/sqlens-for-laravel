<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Folds keyword casing to one canonical form (upper case) so `select`, `SELECT`
 * and `SeLeCt` are the same keyword to a rule — the last piece of grammar-casing
 * drift a rule must never see. It touches ONLY keywords: an identifier is left
 * exactly as written, because under PostgreSQL upper-casing `"user"` would change
 * which object it names — a semantic error that would otherwise pass as "just
 * formatting".
 *
 * It reads the keyword list from the driver — no list, no `match`, no engine name
 * lives in the core. It runs AFTER identifier normalization, which is what makes
 * the keyword/identifier split decidable: an identifier that shares a name with a
 * keyword is already quoted by that stage (a bare `key` column becomes `"key"`),
 * so a BARE word matching a keyword is unambiguously the keyword — and folding it
 * is safe on both engines (PostgreSQL folds it anyway; MySQL requires a
 * keyword-named identifier to be quoted). A quoted identifier — mixed case and all
 * — survives byte-exact, as does any keyword-looking word inside a string literal,
 * a comment, or a dollar-quoted body.
 *
 * Three-valued: a driver with no keyword list (a missing artifact) or an
 * unterminated dollar-quoted body — whose tagged delimiter leaves the position of
 * the following words genuinely undecidable — abort with a named
 * CanonicalizationFailure the pipeline propagates. A statement already reported
 * undetermined upstream never reaches this stage: the pipeline short-circuits on
 * the first failure, so the earlier reason is carried through unchanged.
 */
final readonly class KeywordCasingNormalizer implements CanonicalizationStage
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
        $keywords = $this->driver->keywords();
        if ($keywords === []) {
            return CanonicalizationFailure::missingCanonicalArtifact('keyword list');
        }

        /** @var array<string, true> $keywordSet */
        $keywordSet = array_fill_keys(array_map(mb_strtoupper(...), $keywords), true);

        $quote = $this->driver->quotingCharacter();
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
                if ($close === false) {
                    return CanonicalizationFailure::unterminatedLiteral('dollar-quoted string');
                }

                $end = $close + strlen($tag);
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

            // A quoted identifier survives byte-exact — never a keyword.
            if ($quote !== '' && $char === $quote) {
                $end = $this->scanQuoted($sql, $i, $quote) ?? $length;
                $out .= substr($sql, $i, $end - $i);
                $i = $end;

                continue;
            }

            if ($this->isBareStart($char)) {
                $end = $this->bareWordEnd($sql, $i);
                $word = substr($sql, $i, $end - $i);
                $upper = mb_strtoupper($word);
                $out .= isset($keywordSet[$upper]) ? $upper : $word;
                $i = $end;

                continue;
            }

            $out .= $char;
            $i++;
        }

        return $out;
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
