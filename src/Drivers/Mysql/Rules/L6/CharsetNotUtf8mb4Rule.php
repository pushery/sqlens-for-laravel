<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Drivers\Mysql\Rules\L2\CopyAlterCharsetRule;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\TextEncoding;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A database, table or column that stores text under something narrower than `utf8mb4`.
 *
 * ## `utf8mb3` is the one that looks solved
 *
 * `latin1` announces itself — nobody believes it holds Unicode. `utf8mb3` is the trap: the name says
 * utf8, it holds everything anyone tests with, and it stores three bytes per character, which is
 * exactly the Basic Multilingual Plane and not one character more. Every emoji is outside it. So is
 * a good deal of CJK, including characters in ordinary personal names.
 *
 * What MySQL does with a value it cannot represent depends on the SQL mode, and the lax case is the
 * dangerous one: the character is replaced or the value truncated at it, **without an error**. The
 * row is stored, altered, and nobody finds out until somebody asks why their name is wrong. MySQL
 * 8.4 deprecates `utf8mb3`, which sets a deadline on top of the correctness argument.
 *
 * ## Three levels, and the database one is the invisible one
 *
 * A column inherits from its table and a table from its database. A schema whose tables are all
 * `utf8mb4` while the database default is `latin1` looks entirely healthy — until the next table is
 * created without an explicit character set, by hand or by a raw-SQL migration, and inherits the
 * old default. Nothing among the existing tables reveals that, which is why the database level is
 * judged as its own subject rather than skipped as redundant.
 *
 * ## What it deliberately does NOT say
 *
 * Which `utf8mb4` collation the object carries. That is a separate decision with separate
 * consequences and it has its own rule and its own id ({@see LegacyCollationRule}), so the two can
 * be ignored, baselined and fixed independently. Chaining them under one id would mean an
 * ignore-list entry for the encoding silences the sorting complaint too.
 *
 * ## It does NOT share an implementation with the lint rule, and that is not a shortcut
 *
 * {@see CopyAlterCharsetRule} judges
 * `ALTER TABLE … CONVERT TO CHARACTER SET` — which is the FIX for what this rule reports, and it
 * judges it because the conversion re-encodes every row under a lock. The two ask opposite
 * questions: one asks what a statement costs, the other what a state is. There is no predicate to
 * share, and a base class holding both would be two rules wearing one name.
 *
 * The downtime class therefore stays where the operation is. This rule reports none: an observation
 * about a state has no duration, and a second class stated here would be free to drift from the
 * matrix.
 *
 * ## Why level 6 when the failure is real data loss
 *
 * Because the object is not broken — it is narrow, and whether that bites depends on what the
 * application puts in it. A schema that will only ever hold ASCII part numbers loses nothing. Level
 * 6 is the appetite for being told; a project that wants this to fail a build raises its level,
 * which is what the levels are for.
 */
final class CharsetNotUtf8mb4Rule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * BOTH, and the second was missed on the first pass: the rule judges a database-default COLLATION
     * subject as well as a table, and the branch that decides which lives behind
     * {@see TextEncoding::isDatabaseDefault()} — invisible to a guard reading only this file's own
     * type checks. Declaring `Table` alone was the mirror of the over-claim: the run would have said
     * this check never ran on a reading that handed it exactly its subject.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Collation, SchemaObjectType::Table];
    }

    /** The one answer this rule steers toward — MySQL's only complete UTF-8. */
    private const string WANTED = 'utf8mb4';

    /**
     * The character sets that hold no characters, and are therefore not this rule's business.
     *
     * `binary` is a character set in the catalog's bookkeeping and a byte string in practice: a
     * `VARBINARY` column has no text to encode, so demanding `utf8mb4` of it would be advice that
     * makes the column wrong.
     *
     * @var list<string>
     */
    private const array NOT_TEXT = ['binary'];

    public function id(): string
    {
        return 'MY.L6.CHARSET_NOT_UTF8MB4';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Idiom;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if (TextEncoding::isDatabaseDefault($object)) {
            return $this->judgeDatabase($object);
        }

        return $object->type === SchemaObjectType::Table ? $this->judgeTable($object) : [];
    }

    /** @return list<RuleVerdict> */
    private function judgeDatabase(SchemaObject $object): array
    {
        $charset = $object->getString('charset');

        if ($charset === null || $charset === '') {
            return [RuleVerdict::undetermined(sprintf(
                'The database %s reported no default character set, so what a table created without an explicit '
                .'one would inherit could not be read. That is not a pass: an unread default and a correct '
                .'default look identical from here.',
                $object->qualifiedName,
            ), UndeterminedReason::TextEncodingUnknown)];
        }

        if ($this->acceptable($charset)) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            'The database %s defaults to %s, so every table created in it without an explicit CHARACTER SET '
            .'inherits that — a hand-written CREATE TABLE, a raw-SQL migration, a table added by an operator. '
            .'%s Existing tables say nothing about this: they carry their own character set, and the default is '
            .'invisible until the next one is created. Change it with ALTER DATABASE %s CHARACTER SET utf8mb4 '
            .'COLLATE utf8mb4_0900_ai_ci; that alters no existing table, so it is a safe first step and not the '
            .'whole job.',
            $object->qualifiedName,
            $charset,
            $this->why($charset),
            $object->qualifiedName,
        ))];
    }

    /** @return list<RuleVerdict> */
    private function judgeTable(SchemaObject $object): array
    {
        $tableCharset = $object->getString('charset');

        if ($tableCharset === null || $tableCharset === '') {
            return [RuleVerdict::undetermined(sprintf(
                '%s reported no character set, so what it stores text under could not be read — some storage '
                .'engines carry none. The columns on it were not judged either, because a column reported '
                .'without its table default cannot be placed.',
                $object->qualifiedName,
            ), UndeterminedReason::TextEncodingUnknown)];
        }

        $columns = [];
        $found = [];

        foreach (TextEncoding::columnCharsets($object) as $column => $charset) {
            if (! $this->acceptable($charset)) {
                $columns[] = $column.' ('.$charset.')';
                $found[] = strtolower($charset);
            }
        }

        $tableOffends = ! $this->acceptable($tableCharset);

        if ($tableOffends) {
            $found[] = strtolower($tableCharset);
        }

        if ($found === []) {
            return [];
        }

        return [RuleVerdict::flag($this->tableMessage($object, $tableOffends ? $tableCharset : null, $columns, $found))];
    }

    /**
     * ONE message for the table and everything on it.
     *
     * Not one per column, and the reason is not brevity. A catalog finding is located at the object,
     * and results are deduplicated by rule id and location — so forty column verdicts would arrive
     * as one, chosen arbitrarily, with the other thirty-nine dropped silently. A reader would then
     * convert the single column named and believe the table was finished.
     *
     * @param  list<string>  $columns  already rendered as `name (charset)`, sorted by column name
     * @param  non-empty-list<string>  $found  every offending character set on this table, lower-cased
     */
    private function tableMessage(SchemaObject $object, ?string $tableCharset, array $columns, array $found): string
    {
        $lead = $tableCharset !== null
            ? sprintf('%s stores text as %s.', $object->qualifiedName, $tableCharset)
            : sprintf('%s itself is utf8mb4, but not everything on it is.', $object->qualifiedName);

        $named = $columns === []
            ? ''
            : sprintf(
                ' %s: %s.',
                count($columns) === 1
                    ? 'One column carries its own narrower character set'
                    : count($columns).' columns carry their own narrower character set',
                implode(', ', $columns),
            );

        return $lead.$named.' '.$this->why($this->explain($found)).sprintf(
            ' Converting is ALTER TABLE %s CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci, which '
            .'MySQL performs as a copy of the whole table — plan it as one rather than running it at peak. Note '
            .'also that a utf8mb4 index key is wider, so a legacy index already near the length limit can refuse '
            .'to be rebuilt.',
            $object->qualifiedName,
        );
    }

    /**
     * Which of the offending character sets the message explains, when several are present.
     *
     * `utf8mb3` wins whenever it is there, because it is the one a reader will not believe on their
     * own: `latin1` explains itself. Otherwise the alphabetically first, so the sentence a run
     * produces over an unchanged schema is the same sentence every time.
     *
     * @param  non-empty-list<string>  $found
     */
    private function explain(array $found): string
    {
        sort($found);

        foreach ($found as $charset) {
            if ($charset === 'utf8mb3' || $charset === 'utf8') {
                return $charset;
            }
        }

        return $found[0];
    }

    /** Whether this character set is one this rule has nothing to say about. */
    private function acceptable(string $charset): bool
    {
        return strcasecmp($charset, self::WANTED) === 0
            || in_array(strtolower($charset), self::NOT_TEXT, true);
    }

    /**
     * The consequence, phrased for the character set actually found.
     *
     * `utf8mb3` gets its own sentence because the generic one — "narrower than utf8mb4" — reads like
     * a style note next to a name that says utf8. The whole reason this rule exists is that the name
     * is reassuring and the behavior is not.
     */
    private function why(string $charset): string
    {
        if (strcasecmp($charset, 'utf8mb3') === 0 || strcasecmp($charset, 'utf8') === 0) {
            return 'utf8mb3 is three bytes per character, which is the Basic Multilingual Plane and nothing '
                .'beyond it: every emoji is outside, and so is a good deal of CJK. The name is the trap — it '
                .'says utf8 and it is not. MySQL 8.4 deprecates it, so this has a deadline as well as a cost.';
        }

        return sprintf(
            '%s cannot represent most of Unicode, and depending on the SQL mode MySQL replaces the character or '
            .'truncates the value at it rather than refusing the write. The row is stored, altered, and nobody '
            .'finds out until somebody asks why their name is wrong.',
            $charset,
        );
    }
}
