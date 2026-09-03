<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * What the WHOLE migration does, made available to a rule judging ONE of its
 * statements. A single canonical statement cannot answer "was this table created
 * earlier in the same migration?" — that is a fact about the statements around it —
 * so it is computed once, from every statement's classification, and handed to each
 * one alongside its own canonical form.
 *
 * It exists for exactly the false positive that would otherwise dominate a
 * blocking-DDL rule: an index (or a constraint) built on a table the same migration
 * just created is building against an empty table, holds no lock anyone can observe,
 * and is not the incident the rule warns about. Without this context the rule would
 * flag every create-table-then-index migration — the commonest shape there is — and
 * a linter that cries wolf on the ordinary case is one a team turns off.
 *
 * The set holds canonical, comparison-ready qualified names (schema-qualified when
 * the source was), so a lookup never turns on quoting or letter case.
 */
final readonly class MigrationContext
{
    /**
     * @param  list<string>  $createdTables  canonical qualified names of tables this migration creates
     * @param  list<string>  $columnsWithNotNullCheck  lowercased column names this migration adds a
     *                                                 `CHECK (col IS NOT NULL)` for — the deliberate
     *                                                 safe-pattern marker that lets a later
     *                                                 `SET NOT NULL` on the same column skip its scan
     * @param  list<string>  $createdEnumTypes  lowercased names of enum types this migration creates,
     *                                          so adding a value to one of them is not a rollback
     *                                          concern (the down() drops the whole type)
     * @param  bool  $dropsAConstraint  whether the migration drops any constraint — the signal that
     *                                  tells a CHECK-constraint ADD apart as a CHANGE (drop + add,
     *                                  Laravel's enum() change) rather than a first-time add
     * @param  list<MigrationStatementDigest>  $statements  the migration's statements in capture order —
     *                                                      the ORDER-sensitive material a rule needs when a
     *                                                      single booleaned fact cannot answer its question
     *                                                      ("is a lock timeout set BEFORE the first strong
     *                                                      lock?"). Empty on a context built outside a
     *                                                      capture; the distilled facts above cover the rules
     *                                                      that do not need order.
     */
    public function __construct(
        public array $createdTables,
        public array $columnsWithNotNullCheck = [],
        public array $createdEnumTypes = [],
        public bool $dropsAConstraint = false,
        public array $statements = [],
        /**
         * What this migration's `down()` amounts to, or null when nothing looked.
         *
         * Null is a third answer, not a default: a run whose pre-scan never saw the file cannot
         * say a `down()` is missing, and a rule that treated null as "missing" would invent a
         * finding out of its own blind spot.
         */
        public ?DownMethodState $downMethodState = null,
        /**
         * What this migration's `down()` would EMIT, or null when the rollback leg was never
         * captured.
         *
         * The same three-valued discipline one field up, and for the same reason: null is
         * "nobody looked", {@see DownLegDigest::of()} with an empty list is "it emits nothing",
         * and an unreadable leg carries its own reason. A rule that collapsed the first into
         * the second would report a rollback it never read as a rollback that destroys nothing.
         */
        public ?DownLegDigest $downLeg = null,
        /**
         * The whole RUN's statements — every migration the run captured in this direction, in run
         * order, this migration's own included.
         *
         * ## Why a rule ever needs to look past its own migration
         *
         * Almost none do, and `$statements` above is deliberately the narrow view. One question
         * cannot be answered inside one file, and it is a question about ABSENCE: "does anything
         * index this table?" A migration that creates a table carries that table's whole index
         * history so far — nothing earlier can have indexed a table that did not exist — but the
         * history does not stop at the end of the file. The everyday remedy for a missing index in
         * Laravel is a NEW migration, because a migration that has run in production is never
         * edited. Reading only the one file therefore reports a foreign key that the very next file
         * indexes, forever, on a file the reader is not allowed to change — and the advice would be
         * to add what has already been added.
         *
         * The run is the honest unit for that question: a table created inside the run cannot have
         * been touched before it, and every migration that will run after this one is in it.
         *
         * ## What it is NOT
         *
         * Not an invitation to judge one migration by another's statements. A finding is located at
         * the statement that carries the mistake, and the surrounding file is what a reader can act
         * on; the run-wide view exists to WITHHOLD a finding the run as a whole disproves, never to
         * produce one a single file does not support.
         *
         * A run may also be a SLICE — the `--file` fast path captures one migration — in which case
         * this is exactly that file's stream. A rule reasoning from absence over a slice is
         * reasoning over less history than a full run has, which is the same direction of error the
         * fast path already carries everywhere else: it sees what it was given.
         *
         * The digests carry their index WITHIN their own migration, so the numbering repeats across
         * files. Order across the run is the list's order; the index is not a run-wide position.
         *
         * @var list<MigrationStatementDigest>
         */
        public array $runStatements = [],
    ) {}

    /** The context of a migration whose statements were never classified — creates nothing known. */
    public static function empty(): self
    {
        return new self([]);
    }

    /**
     * Whether this migration creates the named table in one of its own statements.
     *
     * The name must already be canonical — the value objects that reach a rule
     * (a {@see StatementTarget}'s `qualifiedName()`) are, so a rule never
     * normalizes by hand and two spellings of the same table can never disagree.
     */
    public function createsTable(string $qualifiedName): bool
    {
        return in_array($qualifiedName, $this->createdTables, true);
    }

    /**
     * Whether this migration adds a `CHECK (col IS NOT NULL)` for the given column — the
     * safe pattern that lets a `SET NOT NULL` on it skip the full-table scan. The column
     * name is compared lowercased, the form it is captured in.
     */
    public function hasNotNullCheckFor(string $column): bool
    {
        return in_array(strtolower($column), $this->columnsWithNotNullCheck, true);
    }

    /**
     * Whether this migration creates the named enum type in one of its own statements —
     * adding a value to it is then reversible by the down() that drops the type, so it
     * is not the irreversible change the enum rule warns about. Compared lowercased.
     */
    public function createsEnumType(string $type): bool
    {
        return in_array(strtolower($type), $this->createdEnumTypes, true);
    }

    /**
     * Whether this migration creates any enum type at all — the corroborating signal of
     * the "rebuild to drop a value" pattern (new enum type + a DROP TYPE of the old one).
     */
    public function buildsAnEnumType(): bool
    {
        return $this->createdEnumTypes !== [];
    }
}
