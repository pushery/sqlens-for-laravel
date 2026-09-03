<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Canonical;

/**
 * Brings two catalogs onto one form, so a rule never regexes an engine's spelling and a drift
 * comparison never reports quoting as a change.
 *
 * Driver-neutral by construction: the engine's peculiarities arrive as DATA — the folding rule its
 * server reports, the raw type string its catalog returned. There is no branch on a driver name in
 * here, which is what keeps the third engine from being a rewrite.
 *
 * ## The default expression is where the noise actually lives
 *
 * Two servers describing the same default disagree about whitespace, quoting, casing and casts:
 * `now()` against `CURRENT_TIMESTAMP`, `false` against `0`, `'x'::character varying` against `'x'`.
 * Left alone, every one of those becomes a phantom drift the first time a snapshot is compared —
 * and a comparator that reports changes nobody made is one whose output gets skimmed.
 */
final readonly class CatalogCanonicalizer
{
    public function __construct(private IdentifierFolding $folding) {}

    /** The name a user is shown — only a folding server rewrites it. */
    public function name(string $identifier): string
    {
        return $this->folding->displayName($identifier);
    }

    /** The key that decides whether two names are the same object on this server. */
    public function key(string $identifier): string
    {
        return $this->folding->comparisonKey($identifier);
    }

    /** A schema-qualified name, both parts folded the way this server folds them. */
    public function qualified(?string $schema, string $identifier): string
    {
        return $schema === null || $schema === ''
            ? $this->name($identifier)
            : $this->name($schema).'.'.$this->name($identifier);
    }

    public function type(string $raw, ?int $length = null, ?int $precision = null, ?int $scale = null): CanonicalType
    {
        return CanonicalType::fromRaw($raw, $length, $precision, $scale);
    }

    /**
     * One spelling for a default expression, or null when there is none.
     *
     * Deliberately conservative: it normalizes the SHAPE (whitespace, the casing of the handful of
     * keywords that are keywords, PostgreSQL's `::type` casts on a literal) and leaves the VALUE
     * alone. Rewriting values is where a normalizer starts inventing — `0` and `false` are the same
     * default on MySQL and different literals on PostgreSQL, and a layer that flattened them would
     * be making a semantic claim under the guise of tidying.
     */
    public function defaultExpression(?string $expression): ?string
    {
        if ($expression === null || trim($expression) === '') {
            return null;
        }

        // Every transform below runs OUTSIDE string literals only, and that is the load-bearing
        // part rather than a refinement. Applied to the whole expression they reach into the
        // default's VALUE: `'a  b'` lost its second space, `'a::b'` lost its tail, and `'now'` —
        // a real PostgreSQL default, not a contrivance — came back as `'NOW'`. A normalization
        // step that quietly edits the value it is normalizing is the worst shape a comparison
        // layer can take, because the diff it then prints is one it caused itself.
        // The fallback rides on the same line rather than in a guard below, and that is not style.
        // The pattern is a literal constant, so `preg_split` cannot fail on it — a guard would be a
        // branch no run can enter, the coverage floor would name it, and the next reader would have
        // to work out whether the case is impossible or merely untested.
        $parts = preg_split("/('(?:[^']|'')*')/", trim($expression), -1, PREG_SPLIT_DELIM_CAPTURE) ?: [trim($expression)];

        foreach ($parts as $index => $part) {
            if ($index % 2 === 1) {
                continue; // a quoted literal — the user's value, never ours to touch
            }

            $parts[$index] = $this->foldOutsideLiterals($part);
        }

        return trim(implode('', $parts));
    }

    /** The three normalizations, applied to one stretch of expression that holds no literal. */
    private function foldOutsideLiterals(string $fragment): string
    {
        // PostgreSQL appends the type to a literal default: `'draft'::character varying`. The cast
        // is the catalog's bookkeeping, not the user's default, and it is the single largest source
        // of a diff between two engines describing the same column.
        // The type may be SCHEMA-QUALIFIED and either half may be quoted — a user-defined enum comes
        // back as `'draft'::my_schema.probe_state`. A pattern that stopped at the dot left
        // `'draft'.probe_state` behind: not the default, not the cast, and close enough to a default
        // to pass review. Found against a real server, on the first enum column the reader met.
        $fragment = preg_replace('/::"?[\w ]+"?(\."?[\w ]+"?)?(\([^)]*\))?(\[\])?/', '', $fragment) ?? $fragment;

        // Collapse whitespace, including the newlines a multi-line expression carries.
        $fragment = preg_replace('/\s+/', ' ', $fragment) ?? $fragment;

        // `now()` and `CURRENT_TIMESTAMP` are ONE default written two ways, and MySQL says so
        // itself: handed `default now()` it stores `CURRENT_TIMESTAMP`. PostgreSQL keeps whichever
        // was typed, so without this fold the same schema deployed twice — or once per engine —
        // produces two fingerprints and a drift finding nobody can act on.
        // The precision argument RIDES ALONG rather than being dropped: `CURRENT_TIMESTAMP(3)` is a
        // different default from `CURRENT_TIMESTAMP`, and flattening them would be the
        // over-normalization that turns a real difference into silent green.
        $fragment = preg_replace_callback(
            '/\bnow\s*\(\s*(\d*)\s*\)/i',
            static fn (array $m): string => 'CURRENT_TIMESTAMP'.($m[1] === '' ? '' : '('.$m[1].')'),
            $fragment,
        ) ?? $fragment;

        // The remaining keyword spellings, folded in case only. CURRENT_DATE and CURRENT_TIME are
        // deliberately NOT folded into CURRENT_TIMESTAMP: they carry different types, and a layer
        // that equated them would report a date column and a timestamp column as the same default.
        return preg_replace_callback(
            '/\b(current_timestamp|current_date|current_time)\b/i',
            static fn (array $m): string => mb_strtoupper($m[1]),
            $fragment,
        ) ?? $fragment;
    }

    /**
     * An index's columns as one comparable list.
     *
     * The sort direction rides with each column rather than beside it: an index on `(a ASC, b DESC)`
     * is not the same index as one on `(a DESC, b ASC)`, and a list that dropped the directions
     * would report them as identical. `ASC` is written out even where a server leaves it implicit,
     * so two servers that disagree about what to omit still produce one string.
     *
     * @param  list<array{name: string, descending?: bool}>  $columns
     */
    public function indexColumns(array $columns): string
    {
        return implode(', ', array_map(
            fn (array $column): string => $this->name($column['name']).' '.(($column['descending'] ?? false) ? 'DESC' : 'ASC'),
            $columns,
        ));
    }

    /**
     * A collation name, or null when the column simply uses its database's.
     *
     * Lower-cased because that is how both engines spell them in practice and how a comparison has
     * to treat them; an explicitly-set collation that happens to match the default is still kept,
     * because "chosen" and "inherited" are different facts about a column.
     */
    public function collation(?string $collation): ?string
    {
        return $collation === null || trim($collation) === '' ? null : mb_strtolower(trim($collation));
    }

    /**
     * A routine body reduced to what a comparison may treat as identical — and NO further.
     *
     * ## The server does not do this for you
     *
     * Measured on PostgreSQL 18.4 rather than assumed: `pg_get_functiondef()` reconstructs the
     * SIGNATURE — schema qualification, resolved type aliases, an explicit `LANGUAGE` and volatility
     * — but embeds `prosrc` **byte for byte** between its `$function$` markers. Whitespace, comments
     * and line endings survive it untouched. MySQL's `ROUTINE_DEFINITION` is the stored text, with no
     * reconstruction at all. So whatever normalization a body gets, it gets here.
     *
     * ## What it does, and the two things it deliberately refuses to do
     *
     * It normalizes line endings, drops trailing whitespace per line, and trims the whole body. It
     * does **not** collapse internal runs of whitespace, and it does **not** strip comments.
     *
     * Both refusals are load-bearing, for different reasons. Collapsing whitespace **corrupts string
     * literals** — `'a  b'` and `'a b'` are different values, and no amount of care about SQL keeps a
     * text-level rewrite from meeting one. Stripping comments would hide a real edit: a routine whose
     * only change is a comment IS a changed routine, edited by somebody for a reason, and drift
     * exists to say so.
     *
     * ## Why the minimum suffices
     *
     * Drift compares the live database against a REPLAY of the same migrations. Both sides create the
     * routine from identical SQL, so their bodies are identical unless somebody edited one.
     * Canonicalizing harder would not remove noise that exists — it would remove signal.
     *
     * Trailing whitespace is the one exception worth removing, and it is not hypothetical: an editor
     * that strips it on save would otherwise register as a schema change on the next run.
     */
    public function routineBody(string $body): string
    {
        $normalized = str_replace(["\r\n", "\r"], "\n", $body);
        $lines = array_map(rtrim(...), explode("\n", $normalized));

        return trim(implode("\n", $lines));
    }
}
