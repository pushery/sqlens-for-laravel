<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L2;

use Override;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Mysql\DowntimeClass\MysqlDowntimeClassSource;
use Pushery\SQLens\Drivers\Mysql\Rules\AbstractMysqlRule;
use Pushery\SQLens\Drivers\Mysql\Rules\Support\UniqueKeyIndex;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A foreign key pointing at columns that no unique key of the target table covers.
 *
 * ## This is not a deprecation warning. On MySQL 8.4 the statement FAILS
 *
 * The behavior was measured against a real MySQL 8.4.10 rather than read out of a release note,
 * and it is stronger than "deprecated": `restrict_fk_on_non_standard_key` is **ON by default**, and
 * the server rejects the statement with `ERROR 6125 (HY000): Failed to add the foreign key
 * constraint. Missing unique key …`.
 *
 * | The foreign key references… | MySQL 8.4, default configuration |
 * |---|---|
 * | the target's PRIMARY KEY | accepted |
 * | a column carrying a non-unique index | **ERROR 6125** |
 * | the FIRST column of a composite PRIMARY KEY | **ERROR 6125** |
 * | a non-first column of a composite PRIMARY KEY | **ERROR 6125** |
 * | a column with no index at all | **ERROR 6125** |
 *
 * So the finding is about a deploy that breaks today, on the version this package supports, in the
 * configuration a user gets without doing anything — not about a risk at some future upgrade. The
 * third row is the one that surprises: a PREFIX of a unique key is not a unique key, which is why
 * "covered" here means the key's columns EQUAL the referenced ones.
 *
 * ## The honesty boundary, and why it is not noise
 *
 * A foreign key normally points at a table that already exists, whose indexes live on the server —
 * and the lint suite reads no server. Such a statement is reported as
 * {@see UndeterminedReason::ForeignKeyTargetKeyUnknown}: not flagged, because the ordinary
 * `constrained()` onto a primary key is fine and flagging it would be crying wolf; not passed,
 * because "I did not look" is not "it is fine". The audit suite reads the live catalog and settles
 * it. When the migration creates the target table itself, everything needed IS in the capture and
 * the rule answers outright.
 */
final class ForeignKeyOnNonStandardKeyRule extends AbstractMysqlRule implements DerivesDowntimeClass, ProvidesRemediation
{
    /** What adding a foreign key costs, as the matrix keys it. */
    private const string OPERATION = 'add_foreign_key';

    private readonly MysqlDowntimeClassSource $downtimeClasses;

    /** The considered `none` — making the target key unique is a modeling decision, not a sequence. */
    private readonly NoSafeSequenceTemplate $noSafeSequence;

    public function __construct(string $projectRoot, ?MysqlDowntimeClassSource $downtimeClasses = null)
    {
        parent::__construct($projectRoot);

        $this->downtimeClasses = $downtimeClasses ?? new MysqlDowntimeClassSource;
        $this->noSafeSequence = new NoSafeSequenceTemplate;
    }

    public function id(): string
    {
        return 'MY.L2.FK_TARGET_NON_UNIQUE';
    }

    /**
     * A considered `none`: the fix is a schema decision about the REFERENCED table.
     *
     * Every route out changes what that table promises — add a unique key over exactly the
     * referenced columns, point the key at a key that already exists, or drop the constraint. Which
     * one is right depends on what the relationship means, and two of the three change the target's
     * write behavior for every other consumer of it. A payload that picked one would be making a
     * modeling decision from one statement's worth of context.
     *
     * There is no plan to withhold either, which is what separates this `none` from a gap: MySQL
     * 8.4 REJECTS the statement outright (ERROR 6125), so there is no staged sequence that makes it
     * work — the deploy fails at this line whatever anybody does around it.
     */
    #[Override]
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $verdict = $this->verdict($statement);

        // Flagged only. The undetermined verdict here means the referenced table's keys were not in
        // this migration at all, so whether they cover the columns is unknown — and a `none` about
        // a rejected foreign key would overtake a verdict that says it could not look.
        if (! $verdict instanceof RuleVerdict || $verdict->isUndetermined() || $verdict->isPass) {
            return null;
        }

        return $this->noSafeSequence->payload(
            'sqlens::messages.remediation.no_safe_sequence.fk_target_non_unique',
            'sqlens::messages.remediation.no_safe_sequence.schema_decision_verification',
            $this->id(),
            $this->downtimeClassFor($statement),
        );
    }

    public function level(): Level
    {
        return Level::BlockingDdl;
    }

    /**
     * Asked of the matrix, which — measured, not assumed — declines to answer.
     *
     * `add_foreign_key` is a CONDITIONAL entry: it costs a table copy under a shared lock unless
     * `foreign_key_checks` is off, and whether it is off is a session fact a static reader cannot
     * see. Under the blind context the matrix therefore reports the condition as undecidable and
     * this returns null, so the finding carries no class.
     *
     * That is the arrangement working, not failing. The alternative — naming `rewrite` here because
     * it is the likely case — is exactly the hard-coded class the whole derivation exists to
     * prevent, and it would state a cost on a statement MySQL 8.4 is going to reject anyway.
     */
    public function downtimeClassFor(MigrationStatementView $statement): ?DowntimeClass
    {
        if (! $this->referencedColumnsOf($statement) instanceof ForeignKeyReference) {
            return null;
        }

        return $this->downtimeClasses->forCandidateOperations(
            [self::OPERATION],
            $statement->serverVersion ?? ResolvedServerVersion::unresolvable(),
        )->downtimeClass;
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        $reference = $this->referencedColumnsOf($statement);

        if (! $reference instanceof ForeignKeyReference) {
            return null;
        }

        $keys = UniqueKeyIndex::forTable($statement->migration, $reference->table);

        if ($keys === null) {
            return RuleVerdict::undetermined(
                $this->unknownTargetMessage($reference),
                UndeterminedReason::ForeignKeyTargetKeyUnknown,
            );
        }

        return UniqueKeyIndex::covers($keys, $reference->columns)
            ? null
            : RuleVerdict::flag($this->rejectedMessage($reference));
    }

    /** The referenced table and columns of an `ADD CONSTRAINT … FOREIGN KEY`, or null. */
    private function referencedColumnsOf(MigrationStatementView $statement): ?ForeignKeyReference
    {
        $matched = preg_match(
            '/\bFOREIGN KEY\s*\([^)]*\)\s*REFERENCES\s+(?<table>\S+?)\s*\((?<columns>[^)]*)\)/',
            $statement->canonical,
            $matches,
        );

        if ($matched !== 1) {
            return null;
        }

        $columns = UniqueKeyIndex::columnList($matches['columns']);

        return $columns === []
            ? null
            : new ForeignKeyReference(trim($matches['table'], '`"'), $columns);
    }

    private function rejectedMessage(ForeignKeyReference $reference): string
    {
        return sprintf(
            'This foreign key references %s (%s), and no unique key of that table covers exactly those columns. '
            .'MySQL 8.4 rejects the statement outright — restrict_fk_on_non_standard_key is ON by default, and the '
            .'server answers ERROR 6125, "Failed to add the foreign key constraint. Missing unique key". This is a '
            .'failed deploy, not a future risk. Note that a PREFIX of a composite key does not count: referencing '
            .'the first column of a two-column primary key is rejected just as a non-unique index is. Point the key '
            .'at the target\'s primary key, or add a unique key covering exactly the referenced columns first.',
            $reference->table,
            implode(', ', $reference->columns),
        );
    }

    private function unknownTargetMessage(ForeignKeyReference $reference): string
    {
        return sprintf(
            'This foreign key references %s (%s), a table this migration does not create — so which unique keys it '
            .'carries is on the server, and the lint suite reads no server. MySQL 8.4 rejects a foreign key whose '
            .'referenced columns no unique key covers (ERROR 6125, restrict_fk_on_non_standard_key is ON by '
            .'default), so this is worth confirming: the ordinary case, referencing a primary key, is fine. Check '
            .'that %s has a unique key on exactly (%s) — a prefix of a composite key does not count.',
            $reference->table,
            implode(', ', $reference->columns),
            $reference->table,
            implode(', ', $reference->columns),
        );
    }
}
