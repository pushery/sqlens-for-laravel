<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L2;

use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Drivers\Pgsql\Remediation\NotValidThenValidateTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\ForeignKeyWithoutIndexRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\TouchedTables;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `ALTER TABLE … ADD CONSTRAINT` validates the whole table under a lock before it
 * returns. For a foreign key it reaches a SECOND table: PostgreSQL locks both the table
 * carrying the constraint and the one it references while it installs the enforcing
 * triggers, so a migration that names one table stalls writes to two.
 *
 * The lock is SHARE ROW EXCLUSIVE on both sides, not ACCESS EXCLUSIVE. Measured on
 * PostgreSQL 18.0, inside the transaction:
 *
 *   receiving table   AccessShareLock, ShareRowExclusiveLock
 *   referenced table  AccessShareLock, RowShareLock, ShareRowExclusiveLock
 *
 * No AccessExclusive on either. And the difference is exactly the one a maintenance window
 * is planned around — measured against a held SHARE ROW EXCLUSIVE on the same server:
 *
 *   SELECT  returns immediately   <- readers are not blocked
 *   INSERT  waits, then hits lock_timeout
 *
 * So this blocks writers, not readers. A lock that "conflicts with every other lock" and stalls
 * "all traffic" is ACCESS EXCLUSIVE, and planning for that one here would schedule a read outage
 * nobody needs.
 *
 * The queue effect is real all the same: a long-running read transaction already holding
 * AccessShare does not conflict with SHARE ROW EXCLUSIVE, but any lock request queued behind
 * this one waits, so writers pile up behind a slow validation. That
 * is the mechanism worth planning for, and `lock_timeout` is what bounds it.
 *
 * GoCardless's documented ~15-second outage predates 9.5, which is when the referenced-side
 * lock was weakened; the evidence register now says so rather than presenting it as current.
 *
 * Two remediations, and the finding names the right one:
 *
 *  - FOREIGN KEY and CHECK support `NOT VALID`: add the constraint NOT VALID (a fast
 *    metadata change under a brief lock), then `VALIDATE CONSTRAINT` in a separate
 *    migration, which scans the table under a weaker lock that does not block reads
 *    and writes. A constraint already added `NOT VALID` is the safe form and draws
 *    no finding.
 *  - PRIMARY KEY and UNIQUE do NOT support `NOT VALID` — recommending it would be
 *    wrong. The safe path is a `CREATE UNIQUE INDEX CONCURRENTLY` followed by
 *    `ADD CONSTRAINT … USING INDEX`, which promotes the ready-built index without
 *    the validating scan — and that `USING INDEX` form draws no finding, just as an
 *    FK or CHECK already marked `NOT VALID` does; firing on it would cry wolf on the
 *    very fix this rule recommends.
 *
 * **The same-migration exceptions, and there are two.** A constraint added to a table
 * the migration just created locks nothing live, so a statement whose tables are all
 * new is beneath notice. The second is narrower and is what the incident above turns
 * on: this form differs from `NOT VALID` in exactly one thing, the scan of rows
 * ALREADY in the altered table. A table born empty in this migration has none, so the
 * locks — including the one on a live referenced table — are taken and released
 * identically either way, and the advice would split one migration into two without
 * shortening anything. `Schema::create()` with `foreignId()->constrained()` is that
 * shape, and it was red from level 2 up until a consumer read it back to us.
 *
 * Born empty means created here, not created from a query, and not written into
 * earlier in the same migration — the create-then-backfill shape keeps its finding,
 * because there the scan is real. Both predicates are read from the classified targets
 * rather than the SQL text, through {@see TouchedTables}, the one reading of them,
 * which {@see ForeignKeyWithoutIndexRule} shares for a different reason.
 *
 * **The classification lives in {@see ConstraintShape}, not here.** Which of the two
 * remediations applies decides both the WORDING of this finding and the SEQUENCE the
 * template hands over, and two readings of one fact is two chances to disagree — with
 * each half looking correct on its own. The rule asks once and words its message from
 * the answer.
 *
 * Detection is on the canonical form — the constraint keywords are normalized there —
 * never on Laravel's raw grammar.
 */
final class ConstraintNotValidatedRule extends AbstractPgsqlSafetyRule implements DeclaresOperationClass, ProvidesRemediation
{
    /**
     * The one template this rule hands out, built once — it reads the shipped evidence register to
     * fill its references, and that read is free once per run and a growing bill per finding.
     */
    private readonly NotValidThenValidateTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NotValidThenValidateTemplate;
    }

    public function id(): string
    {
        return 'PG.L2.CONSTRAINT_NOT_VALIDATED';
    }

    /**
     * Validation reads every existing row once to prove the predicate holds. It takes a weaker lock than
     * a rewrite and does no writing, so the same row count is worth markedly less alarm here — which
     * is precisely why the class has to be known before the number is read.
     */
    public function operationClass(): string
    {
        return 'constraint_validation';
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /**
     * Blocking: adding the constraint validates existing rows under a lock, degrading
     * a live table without rewriting it. A reader plans a maintenance window around it.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Blocking;
    }

    /**
     * The safe sequence for this statement — whichever of the two it is.
     *
     * The shape is asked of {@see ConstraintShape} exactly as {@see judge()} asks it, so the
     * material can never recommend `NOT VALID` for the constraint the message correctly told
     * somebody to promote from an index instead.
     *
     * Null is unreachable in practice — the collector only asks about a statement this rule
     * flagged, and a flagged statement has a shape — but it is the honest answer for the case where
     * it would not, and inventing a sequence for an unclassified statement is exactly what a fix
     * template must never do.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $shape = ConstraintShape::of($statement);

        return $shape instanceof ConstraintShape
            ? $this->template->forConstraint($statement, $shape, $this->id(), $this->downtimeClass())
            : null;
    }

    /**
     * Three-valued, because the classifier has a real third answer.
     *
     * **`ConstraintShape::Unrecognized` is an `undetermined`, never a pass.** `null` is what the
     * shape answers for a form it deliberately clears, so answering it for a form it does not know
     * would read an unconsidered constraint kind as a considered one. PostgreSQL 18's named not-null
     * constraint is such a form, and it performs the exact scan `PG.L2.SET_NOT_NULL_SCAN` exists to
     * report.
     *
     * The seam for this is documented on {@see ReadsMigrationStatements::verdict()}: *a classifier
     * that meets a case its data does not cover overrides this and returns an undetermined rather
     * than a silent pass.* This is that case.
     */
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        if (ConstraintShape::of($statement) === ConstraintShape::Unrecognized) {
            return RuleVerdict::undetermined(
                'this ADD CONSTRAINT installs a constraint kind SQLens does not classify, so it cannot say '
                .'whether the statement validates existing rows under a lock. The kinds it knows are FOREIGN '
                .'KEY, CHECK, PRIMARY KEY, UNIQUE, EXCLUDE and the named NOT NULL form. Read the statement '
                .'and decide by hand: if PostgreSQL validates on ADD, the operation blocks for the length of '
                .'that scan. Reporting this rather than passing silently is deliberate — the alternative is a '
                .'green result over a statement nobody looked at.',
                UndeterminedReason::UnclassifiedConstraintShape,
            );
        }

        return parent::verdict($statement);
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        return match (ConstraintShape::of($statement)) {
            ConstraintShape::NotValidCapable => 'ADD CONSTRAINT without NOT VALID validates every existing row under a lock before '
                .'it returns — and a foreign key locks the referenced table too, stalling traffic to it. '
                .'Add the constraint NOT VALID, then VALIDATE CONSTRAINT in a separate migration, which '
                .'scans under a weaker lock that does not block reads and writes.',
            ConstraintShape::PrimaryKey, ConstraintShape::Unique => 'Adding a PRIMARY KEY or UNIQUE constraint builds its index under a lock that blocks '
                .'writes for the whole build. These do not support NOT VALID; instead CREATE UNIQUE INDEX '
                .'CONCURRENTLY and then ADD CONSTRAINT … USING INDEX, which promotes the ready-built index '
                .'without the validating scan.',
            ConstraintShape::Exclude => 'Adding an EXCLUDE constraint builds its backing index under a lock that blocks '
                .'writes for the whole build — measured on PostgreSQL 18.0, ACCESS EXCLUSIVE together with a '
                .'SHARE lock on the same table. Unlike a foreign key or a check it cannot be deferred: the '
                .'server refuses NOT VALID on an EXCLUDE constraint outright, and there is no USING INDEX '
                .'promotion for it either. So this one needs a maintenance window sized to the index build, '
                .'which is the honest answer rather than a sequence that does not exist.',
            // `Unrecognized` never reaches here: `verdict()` above answers it as an undetermined. Listed
            // so the match stays exhaustive and a future shape cannot fall through to the silent arm.
            ConstraintShape::Unrecognized => null,
            null => null,
        };
    }
}
