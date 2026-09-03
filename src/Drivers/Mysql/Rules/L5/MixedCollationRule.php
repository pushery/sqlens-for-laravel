<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L5;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\TextEncoding;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Two text columns that cannot be compared without converting one of them first.
 *
 * ## This is an index loss, not an inconsistency
 *
 * MySQL cannot compare two strings under different collations. Faced with one, it converts the side
 * with the lower coercibility at RUNTIME — and a converted column can no longer be answered from
 * its own index. The lookup that was a B-tree descent becomes a scan of the table, and nothing about
 * the query says so; `EXPLAIN` shows the missing index and not the reason for it. Where the
 * coercibilities are equal there is no side to convert and the server refuses outright with
 * `Illegal mix of collations`, which at least fails loudly.
 *
 * The join across a foreign key is where this hurts, because it is the join an application runs
 * constantly. A parent lookup that scans the child table is the same shape of damage as an
 * unindexed foreign key, arrived at from a different direction.
 *
 * ## Measured on 8.4.10: the server REFUSES to create this, and there is exactly one way in
 *
 * That measurement is why the rule is worth more than it looks, not less. MySQL rejects a foreign
 * key whose two ends collate differently — error 3780, "incompatible":
 *
 * | Path | `foreign_key_checks = 1` | `foreign_key_checks = 0` |
 * |---|---|---|
 * | `CREATE TABLE` with the key inline | refused | **still refused** |
 * | `ALTER TABLE … MODIFY` a column already in a key | refused | **succeeds — the mismatch persists** |
 *
 * So the state cannot be typed into existence by somebody writing a migration. It arrives the other
 * way: a restore script, a character-set sweep, or a migration tool that turns the checks off around
 * a batch. Afterwards the constraint is there, the columns disagree, every join across it converts,
 * and NOTHING says so — the server will not even let you recreate what it is already holding.
 *
 * A rule for a state the engine refuses to create is exactly the rule nobody thinks to look for.
 *
 * ## Level 5 and `performance`, deliberately — not level-6 idiom
 *
 * Filed as idiom it would be switched off with the whole level-6 band, and a real index loss would
 * disappear along with a set of recommendations about taste. What this describes is not a
 * preference: the query gets slower by a factor that grows with the table.
 *
 * ## Two triggers, ONE finding — because a location can only carry one
 *
 * A catalog finding is located at the object, and results are deduplicated by rule id and location.
 * So a verdict per column and a verdict per foreign-key edge would arrive as one, arbitrarily
 * chosen, with the rest dropped without a word. The rule therefore says everything it found about a
 * table in a single message, naming the within-table columns and the edges separately so a reader
 * can still tell the two apart.
 *
 * The same constraint decides what an unfollowable edge does. A `fail` and an `undetermined` cannot
 * both survive at one location, so a table that has a real mismatch reports it and NAMES the edges
 * that could not be checked in the same message; a table with nothing but unfollowable edges is
 * `undetermined`. Neither case ever comes back as a pass.
 *
 * ## What is deliberately not reported
 *
 * A `_bin` or `_cs` collation differing from its table is a decision: a hash, a token, a base64
 * payload or a case-sensitive technical key is stored that way ON PURPOSE, and telling somebody to
 * unify it would be telling them to break their own uniqueness. Non-text columns never appear at
 * all — they hold nothing to collate.
 *
 * There is no rule-specific allow list. The audit ignore list already suppresses a (rule, object)
 * pair, and it keeps the finding counted and listed under what hid it; a second suppression path
 * would be the one nobody finds again in a report.
 */
final class MixedCollationRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * Tables only — a run that read none produced no subject for this rule, and the report has to be
     * able to say so rather than let the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'MY.L5.COLLATION_MIXED';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    public function category(): Category
    {
        return Category::Performance;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $columns = $this->divergentColumns($object);
        [$edges, $unfollowable] = $this->edgeVerdicts($object);

        if ($columns === [] && $edges === []) {
            return $unfollowable === [] ? [] : [RuleVerdict::undetermined(
                $this->unfollowableMessage($object, $unfollowable),
                UndeterminedReason::ReferencedObjectNotInScope,
            )];
        }

        return [RuleVerdict::flag($this->message($object, $columns, $edges, $unfollowable))];
    }

    /**
     * The table's own columns whose collation differs from the table default, minus the deliberate ones.
     *
     * Compared against the table default rather than against each other, and the difference matters:
     * "these two columns disagree" is quadratic and names no culprit, while "this column was set by
     * hand" points at the line somebody wrote. The default is what every other column has.
     *
     * @return list<string> rendered as `name (collation)`, sorted by column name
     */
    private function divergentColumns(SchemaObject $object): array
    {
        $default = $object->getString('collation');

        if ($default === null || $default === '') {
            return [];
        }

        $divergent = [];

        foreach (TextEncoding::columnCollations($object) as $column => $collation) {
            if (strcasecmp($collation, $default) !== 0 && ! $this->deliberate($collation)) {
                $divergent[] = $column.' ('.$collation.')';
            }
        }

        return $divergent;
    }

    /**
     * The foreign-key edges that cross a collation boundary, and the ones nobody could follow.
     *
     * @return array{0: list<string>, 1: list<string>} mismatched edges, then unfollowable ones
     */
    private function edgeVerdicts(SchemaObject $object): array
    {
        $mismatched = [];
        $unfollowable = [];

        foreach (ForeignKeyIndexCoverage::parse($object->getString('foreign_key_collations') ?? '') as $edge => $sides) {
            // An edge has exactly two sides. Anything else is a projection this rule cannot read —
            // a snapshot written by another version, an entry somebody edited by hand — and reading
            // one side of it would produce a finding about a column that is not there. Silence is
            // the honest answer to a fact that did not arrive.
            if (count($sides) !== 2) {
                continue;
            }

            [$near, $far] = $sides;

            // No `=` on the far side means the edge left the audited scope. The reading says so
            // rather than omitting it, because an edge nobody followed is not an edge that matched.
            if (! str_contains($far, '=')) {
                $unfollowable[] = $edge.' → '.$far;

                continue;
            }

            [$nearColumn, $nearCollation] = explode('=', $near, 2);
            [$farColumn, $farCollation] = explode('=', $far, 2);

            if (strcasecmp($nearCollation, $farCollation) !== 0) {
                $mismatched[] = sprintf(
                    '%s (%s) → %s (%s)',
                    $nearColumn,
                    $nearCollation,
                    $farColumn,
                    $farCollation,
                );
            }
        }

        sort($mismatched);
        sort($unfollowable);

        return [$mismatched, $unfollowable];
    }

    /**
     * Whether this collation differs on purpose.
     *
     * A `_bin` collation is how a hash, a token or a base64 payload is stored so that two values
     * differing only in case stay two values; `_cs` is the same decision spelled for text. Reporting
     * either would be advising somebody to collapse the distinction they built the column for.
     */
    private function deliberate(string $collation): bool
    {
        $collation = strtolower($collation);

        return str_ends_with($collation, '_bin') || str_ends_with($collation, '_cs') || $collation === 'binary';
    }

    /**
     * @param  list<string>  $columns
     * @param  list<string>  $edges
     * @param  list<string>  $unfollowable
     */
    private function message(SchemaObject $object, array $columns, array $edges, array $unfollowable): string
    {
        $parts = [];

        if ($edges !== []) {
            $parts[] = sprintf(
                'These foreign keys join columns under different collations: %s. MySQL cannot compare the two '
                .'without converting one side at runtime, and the converted side stops being answerable from its '
                .'own index — so the parent lookup an application runs constantly scans the child table instead. '
                .'Where neither side outranks the other there is no conversion and the server refuses with '
                .'"Illegal mix of collations", which at least fails loudly.',
                implode('; ', $edges),
            );
        }

        if ($columns !== []) {
            $parts[] = sprintf(
                'On the table itself, %s from the table default %s: %s. Every comparison against a column with '
                .'the default collation converts one of the two, with the same cost.',
                count($columns) === 1 ? 'one column differs' : count($columns).' columns differ',
                (string) $object->getString('collation'),
                implode(', ', $columns),
            );
        }

        if ($unfollowable !== []) {
            $parts[] = $this->unfollowableSentence($unfollowable);
        }

        return sprintf('%s: %s', $object->qualifiedName, implode(' ', $parts));
    }

    /** @param  list<string>  $unfollowable */
    private function unfollowableMessage(SchemaObject $object, array $unfollowable): string
    {
        return sprintf(
            '%s could not be judged for mixed collations. %s Nothing here is a pass: an edge nobody followed and '
            .'an edge that matched look identical from inside this schema.',
            $object->qualifiedName,
            $this->unfollowableSentence($unfollowable),
        );
    }

    /** @param  list<string>  $unfollowable */
    private function unfollowableSentence(array $unfollowable): string
    {
        return sprintf(
            '%s outside the audited scope, so the collation on the other side could not be read: %s. Widen '
            .'sqlens.catalog.schemas to include it, or accept that this edge is unchecked.',
            count($unfollowable) === 1
                ? 'One foreign key points at a table'
                : count($unfollowable).' foreign keys point at tables',
            implode('; ', $unfollowable),
        );
    }
}
