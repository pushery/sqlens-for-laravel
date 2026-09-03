<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Canonical\Classification\StatementClassificationProfile;
use Pushery\SQLens\Canonical\TransactionMarkers;

/**
 * The per-driver canonicalization contract — where a driver contributes its own
 * quirks (quoting, case folding, literal and comment syntaxes, keywords, DDL
 * transaction behavior, driver-specific stages) so the core never has to know
 * them. This is the ONLY place PostgreSQL-vs-MySQL syntax knowledge lives; the
 * normalization stages read it instead of hard-coding a driver.
 *
 * A driver that leaves a required capability empty (no quoting character, no
 * keywords, no string-literal delimiter) is a named undetermined case, not a
 * silent gap — the extension registry validates it.
 */
interface DriverCanonicalization
{
    /** The identifier quoting character — `"` for PostgreSQL, `` ` `` for MySQL. */
    public function quotingCharacter(): string;

    /**
     * Whether an unquoted identifier folds to lower case (PostgreSQL) or is kept
     * as written (MySQL). The identifier-normalization stage reads this instead of
     * assuming one engine's rule.
     */
    public function foldsUnquotedIdentifiersToLowerCase(): bool;

    /**
     * The reserved keyword list used by keyword-casing normalization, upper case.
     * Non-exhaustive by design — a seed the casing stage extends — but never
     * empty: an empty list is a missing capability.
     *
     * @return list<string>
     */
    public function keywords(): array;

    /**
     * The string-literal delimiters the splitter must not split inside — e.g.
     * `'` for a standard SQL string. Never empty.
     *
     * @return list<string>
     */
    public function stringLiteralDelimiters(): array;

    /**
     * The comment syntaxes the splitter must skip — e.g. `--` and `/*` for both
     * engines, plus `#` for MySQL.
     *
     * @return list<string>
     */
    public function commentSyntaxes(): array;

    /**
     * Whether the engine runs DDL inside a transaction (PostgreSQL) or commits it
     * implicitly (MySQL) — the basis for the transaction-assumption mapping.
     */
    public function supportsDdlTransactions(): bool;

    /**
     * Whether the engine supports dollar-quoted string constants (`$tag$ … $tag$`,
     * PostgreSQL) — the statement splitter must not split on a semicolon inside
     * such a body. Read from the driver, never assumed.
     */
    public function supportsDollarQuotedStrings(): bool;

    /**
     * Whether the engine honors a `DELIMITER` redefinition (MySQL routine bodies)
     * — the splitter follows the redefined terminator instead of `;`.
     */
    public function supportsDelimiterRedefinition(): bool;

    /**
     * Whether a backslash escapes the next character inside a string literal
     * (MySQL, by default) or is a literal backslash (PostgreSQL standard strings).
     * The splitter needs this to find where a literal ends; both engines also
     * accept a doubled quote (`''`).
     */
    public function usesBackslashStringEscapes(): bool;

    /**
     * The character that opens a CLIENT directive at the start of a line, or `''`
     * for an engine whose client has none.
     *
     * `psql` reads `\i other.sql` and `\set ON_ERROR_STOP on` itself and never
     * sends them to the server; they are not statements and do not end at a
     * semicolon. A splitter that does not know this reads a whole hand-written
     * file as one enormous statement — silently, because nothing about it is
     * malformed SQL until something tries to run it.
     *
     * `''` rather than `null` to match {@see self::quotingCharacter()}: an absent
     * capability is spelled the same way throughout this contract. MySQL's client
     * has no such syntax, so it declares none.
     */
    public function clientDirectivePrefix(): string;

    /**
     * The driver-specific canonicalization stages, in order. Empty for now — the
     * generic stages cover both engines today; a driver adds a stage here only for
     * a quirk the generic pipeline cannot express.
     *
     * @return list<CanonicalizationStage>
     */
    public function stages(): array;

    /**
     * The statement-recognition data the classifier applies — the shapes that map a
     * canonical statement to its kind and targets. This is the ONE place the engine
     * knows what `CREATE INDEX` or `ALTER TABLE … DROP COLUMN` looks like; the
     * classifier stays a generic matcher. An empty profile is a named undetermined,
     * not a silent "everything unknown".
     */
    public function statementClassification(): StatementClassificationProfile;

    /**
     * The transaction-control markers the resolver looks for in the statement
     * stream — the keywords that open (BEGIN, START) and close (COMMIT, ROLLBACK)
     * a transaction. Read from the driver, never hard-coded; a driver that declares
     * none is a named undetermined, not a silent "no transaction".
     */
    public function transactionMarkers(): TransactionMarkers;
}
