<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\TextEncoding;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A `utf8mb4` object still sorting by a collation from before MySQL 8.0.
 *
 * ## The difference is wrong ORDER, not slow order
 *
 * `utf8mb4_general_ci` predates the Unicode Collation Algorithm implementation MySQL 8.0 brought.
 * It compares by a shortened table that treats whole groups of characters as equal, so it does not
 * merely sort differently — it sorts several languages **wrongly**, and it reports characters as
 * equal that a user would not call equal. `utf8mb4_unicode_ci` and `utf8mb4_unicode_520_ci` are
 * better and still pinned to older Unicode versions.
 *
 * `utf8mb4_0900_ai_ci` implements UCA 9.0.0 and has been the server's own default since 8.0. An
 * object still on a pre-8.0 collation is almost always carrying a decision nobody made — it was
 * created before 8.0, or by a tool that spelled out the old default.
 *
 * ## Why it is a separate rule from the character set
 *
 * {@see CharsetNotUtf8mb4Rule} asks what the object can STORE; this asks how it ORDERS and
 * COMPARES. They fail differently, they are fixed at different times, and a project may reasonably
 * accept one and not the other. Under one id an ignore-list entry for the storage question would
 * silence the sorting one, and the report would stop being able to say which of the two somebody
 * had decided about. Rule ids are public API from 1.0 on, so this is a shape worth getting right
 * before there are users.
 *
 * ## What is deliberately NOT reported
 *
 * - **`_bin` and `_cs` collations.** A binary or case-sensitive collation on a hash, a token or a
 *   technical key is a decision, and usually the right one. Reporting it would be the rule telling
 *   somebody to break their own uniqueness.
 * - **Language-specific 0900 collations** such as `utf8mb4_de_pb_0900_ai_ci`. They ARE the modern
 *   family; picking one is a considered act, not a leftover.
 * - **Anything not `utf8mb4`.** A `latin1_swedish_ci` column has a character-set problem, and that
 *   is the other rule's finding. Reporting it here too would make two rules shout about one object,
 *   and fixing the character set fixes the collation with it.
 *
 * ## The false positive worth stating before you convert
 *
 * Changing a collation changes what counts as EQUAL, and therefore what counts as a duplicate. Rows
 * that coexist happily under `utf8mb4_general_ci` — where several accented forms compare equal to
 * their base letter, and vice versa depending on the pair — can collide against a `UNIQUE` index
 * under `utf8mb4_0900_ai_ci`, and the ALTER then fails on data that was always there. That is not a
 * reason to stay; it is a reason to check before the maintenance window rather than during it.
 */
final class LegacyCollationRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
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

    /**
     * The pre-8.0 `utf8mb4` collations, each with what replaces it.
     *
     * Listed by name rather than derived from "does not contain 0900", and that is deliberate: the
     * derived form would also condemn every future collation family MySQL adds under another name,
     * which is a rule quietly deciding things about a server it has never seen.
     *
     * @var array<string, string>
     */
    private const array LEGACY = [
        'utf8mb4_general_ci' => 'utf8mb4_0900_ai_ci',
        'utf8mb4_unicode_ci' => 'utf8mb4_0900_ai_ci',
        'utf8mb4_unicode_520_ci' => 'utf8mb4_0900_ai_ci',
    ];

    public function id(): string
    {
        return 'MY.L6.COLLATION_LEGACY';
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
        $collation = $object->getString('collation');

        if ($collation === null || $collation === '') {
            return [RuleVerdict::undetermined(sprintf(
                'The database %s reported no default collation, so how a table created without an explicit one '
                .'would sort could not be read. An unread default and a modern default look the same from here, '
                .'so this is not a pass.',
                $object->qualifiedName,
            ), UndeterminedReason::TextEncodingUnknown)];
        }

        $replacement = self::LEGACY[strtolower($collation)] ?? null;

        if ($replacement === null) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            'The database %s defaults to %s, a collation from before MySQL 8.0, so every table created without '
            .'an explicit COLLATE inherits it. %s Set it with ALTER DATABASE %s CHARACTER SET utf8mb4 COLLATE %s; '
            .'that changes no existing table, so it stops the spread without touching data.',
            $object->qualifiedName,
            $collation,
            $this->why($collation),
            $object->qualifiedName,
            $replacement,
        ))];
    }

    /** @return list<RuleVerdict> */
    private function judgeTable(SchemaObject $object): array
    {
        $tableCollation = $object->getString('collation');

        if ($tableCollation === null || $tableCollation === '') {
            return [RuleVerdict::undetermined(sprintf(
                '%s reported no collation, so how it sorts and compares text could not be read — some storage '
                .'engines carry none. Its columns were left unjudged with it: a column collation without the '
                .'table default it may be inheriting cannot be placed.',
                $object->qualifiedName,
            ), UndeterminedReason::TextEncodingUnknown)];
        }

        $columns = [];
        $found = [];

        foreach (TextEncoding::columnCollations($object) as $column => $collation) {
            if (isset(self::LEGACY[strtolower($collation)])) {
                $columns[] = $column.' ('.$collation.')';
                $found[] = strtolower($collation);
            }
        }

        $tableOffends = isset(self::LEGACY[strtolower($tableCollation)]);

        if ($tableOffends) {
            $found[] = strtolower($tableCollation);
        }

        if ($found === []) {
            return [];
        }

        return [RuleVerdict::flag($this->tableMessage($object, $tableOffends ? $tableCollation : null, $columns, $found))];
    }

    /**
     * ONE message for the table and every column on it.
     *
     * A catalog finding is located at the object and results are deduplicated by rule id and
     * location, so a verdict per column would arrive as one with the rest dropped silently — and a
     * reader would convert the single column named and believe the table was done. Aggregating is
     * also the truer report: a collation change is one decision about one table.
     *
     * @param  list<string>  $columns  already rendered as `name (collation)`, sorted by column name
     * @param  non-empty-list<string>  $found  every legacy collation on this table, lower-cased
     */
    private function tableMessage(SchemaObject $object, ?string $tableCollation, array $columns, array $found): string
    {
        $lead = $tableCollation !== null
            ? sprintf('%s sorts by %s, a collation from before MySQL 8.0.', $object->qualifiedName, $tableCollation)
            : sprintf('%s has a modern collation, but not everything on it does.', $object->qualifiedName);

        $named = $columns === []
            ? ''
            : sprintf(
                ' %s: %s.',
                count($columns) === 1
                    ? 'One column carries its own pre-8.0 collation'
                    : count($columns).' columns carry their own pre-8.0 collation',
                implode(', ', $columns),
            );

        sort($found);

        return $lead.$named.' '.$this->why($found[0]).sprintf(
            ' Converting is ALTER TABLE %s CONVERT TO CHARACTER SET utf8mb4 COLLATE %s, which MySQL performs as a '
            .'copy of the whole table. Check the unique indexes first: a new collation changes what counts as '
            .'equal, so rows that have always coexisted can collide during the ALTER and fail it on data nobody '
            .'touched.',
            $object->qualifiedName,
            self::LEGACY[$found[0]] ?? 'utf8mb4_0900_ai_ci',
        );
    }

    /** Why this particular legacy collation is worth moving off, in its own terms. */
    private function why(string $collation): string
    {
        if (strtolower($collation) === 'utf8mb4_general_ci') {
            return 'utf8mb4_general_ci predates MySQL 8.0 and does not implement the Unicode Collation '
                .'Algorithm: it compares by a shortened table that treats whole groups of characters as equal, '
                .'so it does not just sort differently from what a reader expects — for several languages it '
                .'sorts wrongly, and it calls characters equal that a user would not.';
        }

        return sprintf(
            '%s is pinned to a Unicode version from before MySQL 8.0. utf8mb4_0900_ai_ci implements UCA 9.0.0 '
            .'and has been the server default since 8.0; an object still on the older one is usually carrying a '
            .'decision nobody made rather than one somebody defended.',
            $collation,
        );
    }
}
