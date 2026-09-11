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
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Rules\TouchedTables;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `ALTER TABLE … ADD CONSTRAINT` validates the whole table under a lock before it
 * returns. For a foreign key it is worse than that: PostgreSQL takes an
 * AccessExclusive lock on BOTH the table carrying the constraint and the one it
 * references, while it installs the enforcing triggers — and because that lock
 * conflicts with every other lock, one read query already touching the referenced
 * table can stall all traffic to it behind the migration. It is the exact mechanism
 * behind GoCardless's documented ~15-second outage (see the evidence register).
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
            null => null,
        };
    }
}
