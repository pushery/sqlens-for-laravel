<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Stages;

use LogicException;
use Pushery\SQLens\Canonical\CanonicalFormVersion;
use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\CanonicalStatement;
use Pushery\SQLens\Canonical\Classification\SignatureElementKind;
use Pushery\SQLens\Canonical\Classification\StatementSignature;
use Pushery\SQLens\Canonical\Classification\StatementToken;
use Pushery\SQLens\Canonical\Classification\TokenType;
use Pushery\SQLens\Canonical\Identifier;
use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\TransactionContext;
use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The stage that gives rules the alternative to raw-SQL matching: WHAT a statement
 * does (its kind) and WHAT it acts on (its targets). Without it the arch rule
 * "rules never regex raw SQL" would be a ban with no alternative — a rule like
 * "CREATE INDEX without CONCURRENTLY" could only match on the provenance text.
 *
 * It finalizes the pipeline: it tokenizes the already-normalized SQL, applies the
 * driver's ordered statement signatures (first full match wins), and returns a
 * classified CanonicalStatement. Every recognition pattern comes from the driver's
 * StatementClassificationProfile — the classifier itself is a generic matcher with
 * no keyword constant and no per-engine `match` cascade.
 *
 * A statement can have several targets (an index and its table; an added
 * constraint, its table, and a referenced table); the target set is sorted
 * deterministically so the same input always yields the same set in the same order.
 *
 * Three-valued, and the convenient classification is the dangerous one here:
 *  - a form the driver has no signature or fallback for is `undetermined`
 *    (UnrecognizedStatementForm), never quietly `ddl_other`;
 *  - a recognized shape whose target slot is not a resolvable identifier is
 *    `undetermined` (AmbiguousTarget), never an empty target set passed off as fine;
 *  - a driver with no signatures at all is `undetermined` (a missing artifact);
 *  - a statement already reported undetermined upstream never reaches here — the
 *    pipeline short-circuits and carries the original reason through.
 * `Unknown` (a recognized statement of no modeled kind) is a DELIBERATE result and
 * stays distinguishable from any of these.
 */
final readonly class StatementClassifier implements CanonicalizationStage
{
    public function __construct(private DriverCanonicalization $driver) {}

    public function __invoke(RawStatement $statement, SubjectContext $context): mixed
    {
        $classification = $this->classify($statement->sql);
        if ($classification instanceof CanonicalizationFailure) {
            return $classification;
        }

        [$kind, $targets, $columns] = $classification;

        return new CanonicalStatement(
            canonicalSql: $statement->sql,
            origin: $statement->origin,
            transaction: $statement->transaction ?? TransactionContext::fromMigratorFlag($statement->withinTransaction),
            formVersion: CanonicalFormVersion::current(),
            statementKind: $kind,
            targets: $targets,
            keyColumns: $columns,
        );
    }

    /**
     * @return array{StatementKind, list<StatementTarget>, list<string>}|CanonicalizationFailure
     */
    private function classify(string $sql): array|CanonicalizationFailure
    {
        $profile = $this->driver->statementClassification();
        if ($profile->signatures === []) {
            return CanonicalizationFailure::missingCanonicalArtifact('statement classification signatures');
        }

        $tokens = $this->tokenize($sql);

        foreach ($profile->signatures as $signature) {
            $match = $this->match($signature, $tokens, $profile->modifiers);
            if ($match instanceof CanonicalizationFailure) {
                return $match;
            }

            if ($match !== null) {
                [$targets, $columns] = $match;

                return [$signature->kind, $this->sortTargets($targets), $columns];
            }
        }

        return $this->fallback($tokens, $profile->leadFallback);
    }

    /**
     * Apply one signature to the tokens.
     *
     * @param  list<StatementToken>  $tokens
     * @param  list<string>  $modifiers
     * @return array{list<StatementTarget>, list<string>}|CanonicalizationFailure|null null = no match; failure = a resolvable target was expected but absent
     */
    private function match(StatementSignature $signature, array $tokens, array $modifiers): array|CanonicalizationFailure|null
    {
        $index = 0;
        $count = count($tokens);
        $targets = [];
        $columns = [];

        foreach ($signature->elements as $element) {
            switch ($element->kind) {
                case SignatureElementKind::Keyword:
                    if ($index >= $count || $tokens[$index]->type !== TokenType::Keyword || $tokens[$index]->text !== $element->keyword) {
                        return null;
                    }

                    $index++;
                    break;

                case SignatureElementKind::OptionalModifiers:
                    while ($index < $count && $tokens[$index]->type === TokenType::Keyword && in_array($tokens[$index]->text, $modifiers, true)) {
                        $index++;
                    }
                    break;

                case SignatureElementKind::SeekKeyword:
                    $found = false;
                    while ($index < $count) {
                        $isMarker = $tokens[$index]->type === TokenType::Keyword && $tokens[$index]->text === $element->keyword;
                        $index++;
                        if ($isMarker) {
                            $found = true;
                            break;
                        }
                    }

                    if (! $found) {
                        return null;
                    }
                    break;

                case SignatureElementKind::ColumnList:
                    // A PLAIN parenthesized list — `(a)` or `(a, b)` — captured here rather than
                    // re-read from the string in a rule, which is the whole point: the digest layer
                    // is deliberately free of grammar.
                    //
                    // Each member is an identifier whose PRECEDING symbol is the separator the
                    // position calls for: `(` for the first, `,` for every one after it. That is
                    // what makes `(a varchar_pattern_ops)` — two identifier tokens, exactly like
                    // `(a, b)` in a stream with no punctuation — decline instead of reading as a
                    // two-column index. An index carrying a non-default operator class covers no
                    // equality lookup, so counting it as one would report a foreign key as indexed
                    // while every parent delete still scans: the silent, permanent error.
                    //
                    // A keyword also ends the run, which is what makes
                    // `FOREIGN KEY (a) REFERENCES p (id)` yield `[a]` and not `[a, p, id]`.
                    $captured = [];

                    while ($index < $count
                        && $tokens[$index]->type === TokenType::Identifier
                        && $tokens[$index]->precededBy === ($captured === [] ? '(' : ',')) {
                        $captured[] = $tokens[$index]->text;
                        $index++;
                    }

                    // The list must CLOSE where the run ended. Whatever follows a plain list is
                    // preceded by its `)`; anything else means the parentheses still held something
                    // this profile does not read as a column — a sort option, an operator class, the
                    // arguments of an expression — and the run stopped in the middle of it. Half a
                    // list is the one answer that must not travel: it looks like a complete one.
                    if ($captured === [] || ($index < $count && $tokens[$index]->precededBy !== ')')) {
                        return null;
                    }

                    $columns = [...$columns, ...$captured];
                    break;

                case SignatureElementKind::BackfillTargets:
                    // The columns a `SET` clause writes to FROM OTHER COLUMNS — a data move, not
                    // every assignment. Two properties of each token decide which names are targets,
                    // and BOTH are needed; see the kind's docblock for the measurement that refuted
                    // the one-property reading.
                    //
                    //   depth 0            it is in the clause itself, not inside an expression
                    //   precededBy         null for the first target, `,` for every later one
                    //
                    // ⚠️ And a THIRD property decides whether a target is kept: whether its own
                    // value mentions a column at all. `SET status = 'new'` and
                    // `SET total_cents = amount * 100` are the same shape and different events —
                    // one gives a new column a value, the other moves data out of an existing one.
                    // Measured on a committed fixture: without this, the debt rule that asks "was
                    // this column back-filled" fired on the most ordinary migration there is.
                    $assigned = [];
                    $sawIdentifier = false;
                    $pending = null;
                    $pendingSourced = false;

                    while ($index < $count) {
                        $token = $tokens[$index];

                        // A keyword at the top level ends the clause. One inside a subquery does
                        // not: in `SET a = (SELECT 1), b = other WHERE id = 1` a depth-blind loop
                        // stops at `SELECT` with nothing assigned yet and declines, answering `[]`
                        // over a statement that plainly moves data into `b`. With the depth check
                        // the run reaches the `WHERE` and answers `[b]`.
                        //
                        // ⚠️ This comment used to illustrate the point with `SET a = (SELECT …),
                        // b = 2`, and that example proves nothing: MEASURED, both readings answer
                        // `[a]`. The literal `2` never makes `b` a target under the sourced test
                        // below, so the half-answer the old wording warned about cannot arise
                        // there. The example above is the one where the two readings differ.
                        if ($token->type === TokenType::Keyword && $token->depth === 0) {
                            break;
                        }

                        $isTarget = $token->type === TokenType::Identifier
                            && $token->depth === 0
                            && $token->precededBy === ($assigned === [] && $pending === null ? null : ',');

                        // The FIRST identifier decides whether this is a clause this element reads
                        // at all. PostgreSQL's row-wise form — `SET (a, b) = (1, 2)` — opens with an
                        // identifier at depth 1, and reading on would collect `b` alone, because it
                        // sits behind a comma just as a second assignment would.
                        if (! $sawIdentifier && $token->type === TokenType::Identifier && ! $isTarget) {
                            return null;
                        }

                        if ($token->type === TokenType::Identifier) {
                            $sawIdentifier = true;
                        }

                        if ($isTarget) {
                            // The previous assignment is settled the moment the next one starts.
                            if ($pending !== null && $pendingSourced) {
                                $assigned[] = $pending;
                            }

                            $pending = $token->text;
                            $pendingSourced = false;
                        } elseif ($token->type === TokenType::Identifier) {
                            // Any identifier that is not a target belongs to the value being
                            // assigned — the column this move reads from, or one inside the
                            // expression around it. Either way the assignment reads a column.
                            $pendingSourced = true;
                        }

                        $index++;
                    }

                    if ($pending !== null && $pendingSourced) {
                        $assigned[] = $pending;
                    }

                    // Decline unless the run ended where a `SET` clause legitimately ends — at one
                    // of the terminators the driver named, or at the end of the statement. The
                    // terminators are engine vocabulary and therefore come from the driver.
                    if ($assigned === []) {
                        return null;
                    }

                    if ($index < $count && ! in_array($tokens[$index]->text, $element->clauseTerminators, true)) {
                        return null;
                    }

                    $columns = [...$columns, ...$assigned];
                    break;

                case SignatureElementKind::EndOfStatement:
                    if ($index < $count) {
                        return null;
                    }
                    break;

                case SignatureElementKind::Target:
                    $type = $element->targetType ?? throw new LogicException('a Target element must carry a type');

                    if ($index >= $count || $tokens[$index]->type !== TokenType::Identifier) {
                        return CanonicalizationFailure::ambiguousTarget(
                            sprintf('the %s target of a recognized statement is not a resolvable identifier', $type->value),
                        );
                    }

                    $identifier = Identifier::parse($tokens[$index]->text, $this->driver);
                    if ($identifier instanceof CanonicalizationFailure) {
                        return $identifier;
                    }

                    $targets[] = new StatementTarget($type, $identifier, $element->targetRole);
                    $index++;
                    break;
            }
        }

        return [$targets, $columns];
    }

    /**
     * No signature matched: assign the fallback kind for the leading keyword, or
     * report the form undetermined if the driver does not recognize it at all.
     *
     * @param  list<StatementToken>  $tokens
     * @param  array<string, StatementKind>  $leadFallback
     * @return array{StatementKind, list<StatementTarget>, list<string>}|CanonicalizationFailure
     */
    private function fallback(array $tokens, array $leadFallback): array|CanonicalizationFailure
    {
        $lead = $tokens[0] ?? null;
        if ($lead === null || $lead->type !== TokenType::Keyword) {
            return CanonicalizationFailure::unrecognizedStatementForm($lead->text ?? '');
        }

        $kind = $leadFallback[$lead->text] ?? null;

        return $kind === null
            ? CanonicalizationFailure::unrecognizedStatementForm($lead->text)
            : [$kind, [], []];
    }

    /**
     * @param  list<StatementTarget>  $targets
     * @return list<StatementTarget>
     */
    private function sortTargets(array $targets): array
    {
        // The role is the LAST tiebreak, and only a tiebreak.
        //
        // Determinism does not need it — PHP's sort is stable and the two keys above already order
        // every real statement — but two targets that agree on type AND qualified name would then be
        // ordered by input position, which is the one thing this sort exists to remove. Appending it
        // costs nothing and leaves every committed canonical golden byte-identical, because no
        // statement in the corpus has two same-named targets of one type.
        usort($targets, static fn (StatementTarget $a, StatementTarget $b): int => [$a->type->value, $a->qualifiedName(), $a->role->value] <=> [$b->type->value, $b->qualifiedName(), $b->role->value]);

        return $targets;
    }

    /**
     * Tokenize the canonical SQL into keyword and identifier tokens, skipping
     * whitespace, symbols, literals, comments and dollar-quoted bodies — none of
     * which carry a kind or a target. An identifier chain (`public."users"`) is one
     * token, handed on for Identifier::parse.
     *
     * A skipped SYMBOL is not forgotten entirely: each token records the last one in front of it
     * ({@see StatementToken::$precededBy}), because `(a, b)` and `(a opclass)` are otherwise the
     * same stream and only one of them is a column list.
     *
     * @return list<StatementToken>
     */
    private function tokenize(string $sql): array
    {
        $keywordSet = array_fill_keys(array_map(mb_strtoupper(...), $this->driver->keywords()), true);
        $quote = $this->driver->quotingCharacter();
        $literals = $this->driver->stringLiteralDelimiters();
        $commentMarkers = $this->driver->commentSyntaxes();
        $lineComments = array_values(array_filter($commentMarkers, static fn (string $marker): bool => $marker !== '/*'));
        $hasBlockComment = in_array('/*', $commentMarkers, true);

        $tokens = [];
        $length = strlen($sql);
        $i = 0;
        $separator = null;
        // How many parentheses are open. See StatementToken::$depth for why one character of
        // "what came before me" cannot answer "am I inside something".
        $depth = 0;

        while ($i < $length) {
            $char = $sql[$i];
            $rest = substr($sql, $i);

            if ($this->matchPrefix($rest, $lineComments) !== null) {
                $newline = strpos($sql, "\n", $i);
                $i = $newline === false ? $length : $newline;

                continue;
            }

            if ($hasBlockComment && str_starts_with($rest, '/*')) {
                $close = strpos($sql, '*/', $i + 2);
                $i = $close === false ? $length : $close + 2;

                continue;
            }

            if ($this->driver->supportsDollarQuotedStrings() && $char === '$' && preg_match('/\A\$\w*\$/', $rest, $matches) === 1) {
                $tag = $matches[0];
                $close = strpos($sql, $tag, $i + strlen($tag));
                $i = $close === false ? $length : $close + strlen($tag);

                continue;
            }

            $literal = $this->matchPrefix($rest, $literals);
            if ($literal !== null) {
                $i = $this->scanQuoted($sql, $i, $literal) ?? $length;

                continue;
            }

            if ($char === $quote || $this->isBareStart($char)) {
                $end = $this->chainExtent($sql, $i, $quote);
                $text = substr($sql, $i, $end - $i);
                $tokens[] = $this->classifyToken($text, $keywordSet, $separator, $depth);
                $separator = null;
                $i = $end;

                continue;
            }

            // The one branch a symbol reaches. Whitespace separates tokens without saying
            // anything about them; every other character is punctuation the next token records.
            if (! ctype_space($char)) {
                $separator = $char;

                // Never below zero: a stray `)` in text this layer could not otherwise parse must
                // not push every later token to a negative depth, where nothing is at top level and
                // every element declines for a reason no reader could find.
                $depth += $char === '(' ? 1 : ($char === ')' ? -1 : 0);
                $depth = max(0, $depth);
            }

            $i++;
        }

        return $tokens;
    }

    /**
     * @param  array<string, true>  $keywordSet
     * @param  string|null  $precededBy  the last symbol before this token, or null after whitespace
     * @param  int  $depth  how many parentheses are open around it
     */
    private function classifyToken(string $text, array $keywordSet, ?string $precededBy, int $depth): StatementToken
    {
        // A single bare word that is a keyword is a keyword token; a quoted or
        // qualified reference, or a bare non-keyword word, is an identifier.
        if (! str_contains($text, '.')) {
            $upper = mb_strtoupper($text);
            if (isset($keywordSet[$upper])) {
                return new StatementToken(TokenType::Keyword, $upper, $precededBy, $depth);
            }
        }

        return new StatementToken(TokenType::Identifier, $text, $precededBy, $depth);
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
                    return $length;
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
