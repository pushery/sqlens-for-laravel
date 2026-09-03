<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\JudgesMigrationStatements;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\ConstraintNotValidatedRule;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Rules\TouchedTables;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A foreign key whose referencing column no index covers — the showcase of one rule, two subjects.
 *
 * PostgreSQL indexes the REFERENCED side of a foreign key and not the referencing one. So every
 * `DELETE` or `UPDATE` on the parent has to check the child table for rows pointing at the row
 * being changed, and without an index that check is a full scan. On a child table of any size this
 * is the difference between a deploy and an outage — and nothing in the migration that created the
 * key hints at it, which is what makes it worth a rule rather than a habit.
 *
 * ## Why the lint suite answers only about a table this migration creates
 *
 * Against a live schema the catalog holds every index, so this is a fail or a pass.
 *
 * Against a migration it is USUALLY neither. The absence of an index cannot be shown from the SQL
 * a migration emits: the index may have been created three releases ago, in a file this run never
 * read. A fail would be wrong on most healthy projects and a pass would be wrong on exactly the
 * projects this rule exists for.
 *
 * The remaining option — `undetermined` on every foreign key — is what the first draft reported,
 * and it is worse than silence. `$table->foreignId(...)->constrained()` is among the commonest
 * statements a Laravel migration contains, the message would be IDENTICAL every time (it says
 * something about the lint suite's reach, not about this migration), nothing in it can be acted on
 * where it is reported, and under `strict_undetermined` it would fail the lint gate of every
 * project that has foreign keys at all. A finding that is constant across its occurrences and
 * unactionable at its site is documentation wearing a finding's clothes — and this package's own
 * rules keep warning that a linter which cries wolf on the ordinary case is one a team turns off.
 * That silence is the DEFAULT here and stays the default: everything the lint branch below does not
 * decide is reported as nothing at all, never as a pass and never as an undetermined.
 *
 * The one case it CAN decide is the migration that creates the table itself. Nothing earlier can
 * have indexed a table that did not exist, so the only statements that could index it are the ones
 * this RUN captured — and if none of them does, the absence is proven, at the point of the mistake,
 * with the fix one line away. It needs the ordered column lists the classifier now reads off an
 * index and off a key, which is why this half could not be built when the rule shipped.
 *
 * **The history is the RUN's, not the file's, and that is not a detail.** The index may perfectly
 * well arrive in a LATER migration of the same run, and in Laravel that is the only correct place
 * for it: a migration that has run in production is never edited, so a missing foreign-key index —
 * including one this package's own audit suite reported — is back-filled in a new file. Reading
 * only the file being judged made that the everyday false positive: the finding stayed on a file
 * the reader was not allowed to change, and its advice was to add what had already been added. See
 * {@see MigrationContext::$runStatements}.
 *
 * **The candidate indexes are scoped to the TABLE**, read from each statement's own target rather
 * than from the migration wholesale. Column names repeat across tables in every schema — `user_id`,
 * `tenant_id`, `team_id` — so an unscoped reading lets an index on a SIBLING table answer for this
 * one, and the multi-table create migration this branch exists for is exactly where that happens.
 * That mistake is the silent kind: a genuinely unindexed key reported as clean.
 *
 * **"Created here" means EVERY table the statement touches** — the same predicate
 * {@see ConstraintNotValidatedRule} uses, from the same {@see TouchedTables}, though for a
 * different reason: there it is about what MATTERS (a key from a new table to a live one still
 * locks the live one), here about what can be KNOWN. A foreign key names two tables and the
 * classifier sorts a statement's targets for determinism, so which of the two CARRIES the key is
 * not recoverable from the projection a rule sees. With both tables born in this migration the
 * referencing one certainly was; with only one of them born here it could be either, and firing
 * would report a table whose index history this run never read. So the sound condition is both —
 * which under-reports the new-child-referencing-an-existing-parent shape, and under-reporting is
 * the direction this rule is allowed to be wrong in, because the audit suite still answers it in
 * full against the catalog.
 *
 * The same ambiguity governs coverage: the key is on one of the two tables and nobody knows which,
 * so the finding is withheld unless NEITHER of them is covered and BOTH of their histories could
 * be read. An index on the referenced table rarely leads with the referencing column, so this
 * costs little in practice — and what it costs, it costs in silence.
 *
 * **Coverage is decided by {@see ForeignKeyIndexCoverage::isCovered()}, the same left-prefix test
 * the catalog half runs, over a candidate set held to the same standard as the catalog's
 * `comparable_indexes`.** That standard is the whole reason the two halves can be trusted together:
 * the catalog excludes a partial, expression or non-default-operator-class index because none of
 * them serves a referential lookup, and this half excludes them by reading a column list only off
 * the plain `CREATE INDEX <i> ON <t> (<c>, …)` form — a predicate, an operator class or a sort
 * option makes the classifier decline, and an index it declined counts as nothing. What it must
 * never do is COUNT one: an operator class swept into the column run would report a scanning table
 * as covered, silently and permanently.
 *
 * An index this branch cannot read is not simply uncounted, it STOPS the finding for that table.
 * The claim rests on holding the table's complete index history, and a `CREATE INDEX` whose columns
 * could not be read is a hole in it — the run creates an index and nobody knows what it is over.
 * The alternative (report anyway) would fire on shapes the catalog calls perfectly comparable, such
 * as an explicit `USING btree` or an INCLUDE payload, which is the one direction this branch may
 * not be wrong in: it may say the same thing EARLIER than the audit suite, never something else.
 *
 * **What this branch reads as coverage.** A `CREATE INDEX`, and the two constraints PostgreSQL
 * IMPLEMENTS with an index — `UNIQUE` and `PRIMARY KEY` — whose columns the classifier now carries
 * for exactly this reason. Without them the textbook pivot table was a false positive:
 * `$table->unique(['team_id', 'user_id'])` covers the key on `team_id`, the rule reported it
 * anyway, and the index it recommended is one `PG.L7.REDUNDANT_INDEX` then reports as redundant to
 * the unique it was already covered by. The remaining gap is narrow and hand-written: a constraint
 * spelled in a form this profile reads no column list off — measured, `UNIQUE NULLS NOT DISTINCT (…)`
 * is one — is not counted as coverage. Laravel's grammar emits no such form.
 *
 * ## Why there is no MySQL twin, measured rather than assumed
 *
 * InnoDB does not merely usually index a foreign key — it forecloses every case this rule could
 * report. Measured against a real MySQL 8.4.10 server: a composite key with no author-declared
 * index gets one created; an index on `(b, a)` does NOT satisfy a key on `(a, b)`, so InnoDB
 * creates its own (it left-prefix-matches exactly as this rule does); an index on `(a, x)` DOES
 * satisfy a key on `(a)`, so nothing is added; a prefix index `s(10)` does not count and a full
 * index is created beside it; the resulting index cannot be dropped afterwards (`ERROR 1553`); and
 * `foreign_key_checks=0` does not change any of it.
 *
 * A rule registered there would therefore be an arm that cannot fire — and a user reading
 * `MY.L5.FK_NO_INDEX` in the registry would believe SQLens checks this on MySQL, when in truth the
 * engine covers it and SQLens checks nothing. The absence is the honest answer, and a test in the
 * MySQL rule-set suite holds it so a later reader repairs nothing.
 */
final class ForeignKeyWithoutIndexRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, JudgesMigrationStatements
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
        return 'PG.L5.FK_NO_INDEX';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    /**
     * Performance, not safety: nothing is lost or corrupted, the parent delete is simply slow — and
     * classifying it as safety would put it in the band a project gates its deploys on.
     */
    public function category(): Category
    {
        return Category::Performance;
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $foreignKeys = ForeignKeyIndexCoverage::parse($object->getString('foreign_keys') ?? '');

        if ($foreignKeys === []) {
            return [];
        }

        // Only the indexes the reading judged COMPARABLE. A partial or expression index is a real
        // index and it is in `indexes`, but it covers no lookup a foreign key makes — counting it
        // would leave this rule silent about a table that scans on every parent delete.
        $indexes = array_values(ForeignKeyIndexCoverage::parse($object->getString('comparable_indexes') ?? ''));
        $all = ForeignKeyIndexCoverage::parse($object->getString('indexes') ?? '');

        $uncovered = [];
        $unreadable = [];

        foreach ($foreignKeys as $name => $columns) {
            if ($columns === []) {
                $unreadable[] = $name;

                continue;
            }

            if (ForeignKeyIndexCoverage::isCovered($columns, $indexes)) {
                continue;
            }

            $uncovered[$name] = $columns;
        }

        // ONE verdict for the table, naming every key.
        //
        // Results are deduplicated by rule id and LOCATION, and a catalog finding is located at the
        // OBJECT — there is no component for a member. A verdict per key therefore arrived as one
        // with the rest dropped without a word, which this rule did from the day it merged: a table
        // with two unindexed foreign keys reported one, the reader added that index, considered the
        // table done, and the second key went on scanning on every parent delete. The report never
        // looked incomplete.
        if ($uncovered !== []) {
            return [RuleVerdict::flag($this->message($object, $uncovered, $unreadable, $indexes, $all))];
        }

        if ($unreadable === []) {
            return [];
        }

        return [RuleVerdict::undetermined(sprintf(
            'On %s, the columns of %s could not be read, so whether an index covers %s is unknown.',
            $object->getString('logical_name') ?? $object->qualifiedName,
            $this->list($unreadable),
            count($unreadable) === 1 ? 'it' : 'them',
        ), UndeterminedReason::TableKeyUndetermined)];
    }

    /**
     * The verdict about ONE migration statement — a fail only for the case the run itself settles,
     * and silence for everything else.
     *
     * Every condition is argued in the class docblock. They are written as early returns in the
     * order that costs least: the kind first (most statements are not a constraint at all), then
     * the shape, then the columns, then the migration-wide question, and the walk over the run's
     * statement stream last.
     */
    public function judgeStatement(MigrationStatementView $statement): ?RuleVerdict
    {
        // `AddForeignKey` is the kind a driver whose profile names the shape directly assigns; the
        // PostgreSQL profile reaches an added key through the generic `AddConstraint` signature.
        if (! $statement->is(StatementKind::AddConstraint) && ! $statement->is(StatementKind::AddForeignKey)) {
            return null;
        }

        // …and that generic kind is shared with the two constraints PostgreSQL backs with an index,
        // which carry a column list of their own — so the column list can no longer tell a key from
        // a UNIQUE or a PRIMARY KEY. The REFERENCES clause is what makes a constraint a foreign key,
        // and its keywords are normalized in the canonical form: the same reading
        // {@see ConstraintNotValidatedRule} tells the two apart by, never Laravel's raw grammar.
        // Without it, `$table->string('slug')->unique()` would be judged as a key on `slug`.
        if (! str_contains($statement->canonical, 'FOREIGN KEY')) {
            return null;
        }

        $columns = $statement->keyColumns;

        // No columns is not "a key of no columns" — it is the shape the classifier could not read.
        // There is nothing to ask a coverage question about.
        if ($columns === []) {
            return null;
        }

        if (! TouchedTables::allCreatedHere($statement)) {
            return null;
        }

        // The key sits on ONE of the tables this statement names and the projection cannot say
        // which, so every one of them has to come out uncovered AND fully readable before the
        // absence is something this branch may assert.
        foreach (TouchedTables::of($statement) as $table) {
            $indexes = $this->indexesOn($table->qualifiedName(), $statement->migration->runStatements);

            if ($indexes === null || ForeignKeyIndexCoverage::isCovered($columns, $indexes)) {
                return null;
            }
        }

        // The columns appear twice on purpose — once as the fact and once inside the advice. The
        // fix has a SHAPE (leftmost), and a reader who has to carry the column list back up the
        // sentence to apply it is the reader who adds an index in the wrong order.
        return RuleVerdict::flag(sprintf(
            'This migration creates the table and adds a foreign key on (%1$s) with no index '
            .'covering it, so every DELETE or UPDATE on the parent will scan this table. Nothing '
            .'earlier can have indexed a table that did not exist yet, and no migration in this run '
            .'indexes it either. Add an index whose leftmost columns are (%1$s).',
            implode(', ', $columns),
        ));
    }

    /**
     * The key columns of every index this RUN puts on one table — or null when the run puts one
     * there whose columns could not be read.
     *
     * Null is the third value, and it is the whole reason this returns a list rather than filling
     * one: an index nobody could read is not an index that covers nothing, it is a hole in the
     * history the finding rests on. Only a `CREATE INDEX` produces it — a constraint form this
     * profile reads no columns off is left uncounted rather than treated as a hole, because a
     * CHECK constraint is column-less by nature and bailing on one would silence the rule for every
     * migration that adds a check to the table it is creating.
     *
     * Scoped by the statement's OWN table target, not by the run wholesale: `soleTarget` answers
     * only when a statement names exactly one table, which is true of every index and every
     * index-backed constraint and false of the foreign key itself (it names two), so a key can
     * never be mistaken for an index over its own columns.
     *
     * @param  list<MigrationStatementDigest>  $statements
     * @return list<list<string>>|null
     */
    private function indexesOn(string $table, array $statements): ?array
    {
        $indexes = [];

        foreach ($statements as $digest) {
            if ($digest->soleTarget(SchemaObjectType::Table)?->qualifiedName() !== $table) {
                continue;
            }

            if ($digest->kind === StatementKind::CreateIndex) {
                if ($digest->keyColumns === []) {
                    return null;
                }

                $indexes[] = $digest->keyColumns;

                continue;
            }

            // A UNIQUE or a PRIMARY KEY constraint. PostgreSQL implements both WITH a b-tree index
            // over exactly the columns they name, so each serves a referential lookup the way a
            // CREATE INDEX does — and they are the only other shapes this profile reads a column
            // list off.
            if ($digest->keyColumns !== []) {
                $indexes[] = $digest->keyColumns;
            }
        }

        return $indexes;
    }

    /**
     * A readable enumeration — `a`, `a and b`, `a, b and c`.
     *
     * @param  list<string>  $items
     */
    private function list(array $items): string
    {
        if (count($items) === 1) {
            return $items[0];
        }

        $last = array_pop($items);

        return implode(', ', $items).' and '.$last;
    }

    /**
     * Both suites, because it really answers in both.
     *
     * `lint` was deliberately absent while the rule had nothing to say about a migration: a rule
     * that claimed a suite it stayed silent in would make the registry advertise an answer no run
     * produces, and the registry export is what a reader trusts to say where a finding can come
     * from. The claim is now earned by the create-the-table branch, and by nothing wider than it.
     *
     * @return list<Suite>
     */
    public function suites(): array
    {
        return [Suite::Lint, Suite::Audit];
    }

    /**
     * ONE message for the table, naming every uncovered key and the index each one needs.
     *
     * An enumeration rather than a sentence per key, because the fix is one decision about one
     * table: somebody opens a migration and adds the indexes together. Any key whose columns could
     * not be read rides along in the same finding — dropping it would hide the one thing the rule
     * could not answer, and a second verdict at this location would be deduplicated away.
     *
     * @param  array<string, list<string>>  $uncovered  key name => its columns
     * @param  list<string>  $unreadable
     * @param  list<list<string>>  $comparable
     * @param  array<string, list<string>>  $all
     */
    private function message(SchemaObject $table, array $uncovered, array $unreadable, array $comparable, array $all): string
    {
        $keys = [];

        foreach ($uncovered as $name => $columns) {
            $keys[] = sprintf('%s (%s)', $name, implode(', ', $columns));
        }

        // When the table HAS indexes that simply cannot be compared, say so. "No index covers this"
        // and "the only index here is one I must not reason about" send a reader to different
        // places, and the second one is where a wrong fix gets made.
        $incomparable = count($all) > count($comparable);

        // With one key the exact columns go in the advice; with several they are already listed
        // above, and repeating them would read as a second, different instruction.
        $single = count($uncovered) === 1;
        $advice = $single
            ? sprintf('Add an index whose leftmost columns are (%s).', implode(', ', reset($uncovered)))
            : 'Add an index for each, whose leftmost columns are the ones named above.';

        return sprintf(
            'On %s, %s %s no index covering %s, so every DELETE or UPDATE on the parent scans this '
            .'table. %s%s%s',
            $table->getString('logical_name') ?? $table->qualifiedName,
            $this->list($keys),
            $single ? 'has' : 'have',
            $single ? 'it' : 'them',
            $advice,
            match ($incomparable) {
                true => ' This table does carry other indexes, but none this check can reason about — a partial, '
                    .'expression or non-default-operator-class index covers no foreign-key lookup.',
                false => '',
            },
            $unreadable === []
                ? ''
                : sprintf(' The columns of %s could not be read, so whether an index covers %s is unknown.',
                    $this->list($unreadable),
                    count($unreadable) === 1 ? 'it' : 'them',
                ),
        );
    }
}
