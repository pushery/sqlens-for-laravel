<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Contracts\DriverCanonicalization;

/**
 * A parsed, canonicalized identifier reference — one object name, optionally
 * schema-qualified. It collapses quoting variants of the SAME object to a single
 * canonical spelling (`"users"` and `users` under PostgreSQL, `` `users` `` and
 * `users` under MySQL all become `users`) and folds case per the driver, WITHOUT
 * touching qualification: `public.users` never collapses to `users`, because that
 * would silently assume a `search_path`. Resolving qualified <-> unqualified is
 * the audit suite's configuration, not this layer's guess; the schema/name split
 * here only prepares the data for it.
 *
 * Three-valued: an unterminated (or malformed) quote, more qualification levels
 * than a schema.name reference can carry, or a driver with no identifier quote
 * each yield a named CanonicalizationFailure — never a silently mis-parsed
 * identifier. All driver quirks (quote character, folding, keyword list) are read
 * through the injected contract; no engine is hard-coded here.
 */
final readonly class Identifier
{
    /** schema.name — column-level qualification is not a table reference. */
    private const int MAX_LEVELS = 2;

    public function __construct(
        public ?IdentifierComponent $schema,
        public IdentifierComponent $name,
    ) {}

    public function wasSchemaQualified(): bool
    {
        return $this->schema instanceof IdentifierComponent;
    }

    /** The canonical rendering — canonical parts joined by a dot; qualification preserved. */
    public function canonical(): string
    {
        return $this->schema instanceof IdentifierComponent
            ? $this->schema->canonical.'.'.$this->name->canonical
            : $this->name->canonical;
    }

    /** The original rendering, exactly as written in the source. */
    public function original(): string
    {
        return $this->schema instanceof IdentifierComponent
            ? $this->schema->original.'.'.$this->name->original
            : $this->name->original;
    }

    public static function parse(string $reference, DriverCanonicalization $driver): self|CanonicalizationFailure
    {
        $quote = $driver->quotingCharacter();
        if ($quote === '') {
            return CanonicalizationFailure::missingCanonicalArtifact('identifier quoting character');
        }

        $segments = self::splitRawSegments(trim($reference), $quote);
        if ($segments instanceof CanonicalizationFailure) {
            return $segments;
        }

        if (count($segments) > self::MAX_LEVELS) {
            return CanonicalizationFailure::tooManyQualificationLevels($reference, count($segments));
        }

        $components = [];
        foreach ($segments as $segment) {
            $component = self::canonicalizeSegment($segment, $driver);
            if ($component instanceof CanonicalizationFailure) {
                return $component;
            }

            $components[] = $component;
        }

        return count($components) === self::MAX_LEVELS
            ? new self($components[0], $components[1])
            : new self(null, $components[0]);
    }

    /**
     * Split a reference into its raw dot-separated segments, keeping quoted parts
     * intact (a dot inside a quoted identifier does not qualify). A quote that is
     * never closed is a named failure, not a guessed split.
     *
     * @return list<string>|CanonicalizationFailure
     */
    private static function splitRawSegments(string $reference, string $quote): array|CanonicalizationFailure
    {
        $segments = [];
        $current = '';
        $length = strlen($reference);
        $i = 0;

        while ($i < $length) {
            $char = $reference[$i];

            if ($char === $quote) {
                $close = self::scanQuoted($reference, $i, $quote);
                if ($close === null) {
                    return CanonicalizationFailure::unterminatedLiteral('quoted identifier');
                }

                $current .= substr($reference, $i, $close - $i);
                $i = $close;

                continue;
            }

            if ($char === '.') {
                $segments[] = $current;
                $current = '';
                $i++;

                continue;
            }

            $current .= $char;
            $i++;
        }

        $segments[] = $current;

        return $segments;
    }

    /**
     * Canonicalize one raw segment into a component. A segment that opens with the
     * quote but is not a single clean quoted token (`"a"b`) is malformed and
     * reported, never silently truncated.
     */
    private static function canonicalizeSegment(string $segment, DriverCanonicalization $driver): IdentifierComponent|CanonicalizationFailure
    {
        $quote = $driver->quotingCharacter();
        $wasQuoted = str_starts_with($segment, $quote);

        if ($wasQuoted) {
            if (self::scanQuoted($segment, 0, $quote) !== strlen($segment)) {
                return CanonicalizationFailure::unterminatedLiteral('quoted identifier');
            }

            // A quoted identifier is exact — folding never applies inside quotes.
            $effectiveName = str_replace($quote.$quote, $quote, substr($segment, 1, -1));
        } else {
            $effectiveName = $driver->foldsUnquotedIdentifiersToLowerCase()
                ? mb_strtolower($segment)
                : $segment;
        }

        return new IdentifierComponent(
            original: $segment,
            canonical: self::render($effectiveName, $driver),
            wasQuoted: $wasQuoted,
        );
    }

    /**
     * The canonical spelling of a bare effective name: rendered without quotes when
     * it round-trips unquoted (a valid, non-keyword identifier that a folding driver
     * would not re-fold), otherwise wrapped in the driver's canonical quote so its
     * exact form survives.
     */
    private static function render(string $name, DriverCanonicalization $driver): string
    {
        $quote = $driver->quotingCharacter();

        $bareSafe = self::isBareIdentifier($name)
            && ! in_array(mb_strtoupper($name), $driver->keywords(), true)
            && (! $driver->foldsUnquotedIdentifiersToLowerCase() || mb_strtolower($name) === $name);

        return $bareSafe
            ? $name
            : $quote.str_replace($quote, $quote.$quote, $name).$quote;
    }

    private static function isBareIdentifier(string $name): bool
    {
        return preg_match('/^[\p{L}_][\p{L}\p{N}_$]*$/u', $name) === 1;
    }

    /**
     * Scan a quoted region from its opening quote at $start to the matching close,
     * honoring a doubled quote as an escape. Returns the index just past the
     * closing quote, or null if it is never closed.
     */
    private static function scanQuoted(string $subject, int $start, string $quote): ?int
    {
        $length = strlen($subject);
        $j = $start + 1;

        while ($j < $length) {
            if ($subject[$j] === $quote) {
                if ($j + 1 < $length && $subject[$j + 1] === $quote) {
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
