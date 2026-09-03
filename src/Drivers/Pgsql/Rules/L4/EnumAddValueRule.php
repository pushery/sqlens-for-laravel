<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\EnumChangeTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\Support\EnumValueAddition;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * `ALTER TYPE … ADD VALUE` looks harmless and is not. Two things a migration author is
 * usually surprised by:
 *
 *  - The new value cannot be USED in the same transaction it is added in. This is the
 *    PostgreSQL 18 reality, and it is stated as exactly that — NOT as the obsolete
 *    blanket "ADD VALUE cannot run in a transaction", which stopped being true in
 *    PostgreSQL 12. Repeating that old rule on this baseline would be a version trap,
 *    and a wrong old rule is worse than a missing one.
 *  - The step is irreversible: a `down()` cannot remove an enum value, so a migration
 *    that adds one cannot be cleanly rolled back.
 *
 * The exception: adding a value to an enum type this SAME migration creates is fine —
 * the `down()` drops the whole type, so there is nothing to roll back and no live
 * consumers of the value. That is read from the migration context, not the SQL around
 * the statement.
 *
 * Detection is on the canonical form, never Laravel's raw grammar.
 */
final class EnumAddValueRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The append sequence this rule hands over, built once. */
    private readonly EnumChangeTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new EnumChangeTemplate;
    }

    public function id(): string
    {
        return 'PG.L4.ENUM_ADD_VALUE';
    }

    /**
     * The append sequence — the only enum change PostgreSQL performs cheaply.
     *
     * Type and value come from the SAME reading {@see judge()} uses, so the material can never name
     * a different value than the finding does.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $addition = EnumValueAddition::of($statement);

        if (! $addition instanceof EnumValueAddition) {
            return null;
        }

        $context = ['type' => $addition->type];

        if ($addition->value !== null) {
            $context['value'] = $addition->value;
        }

        return $this->template->forAddValue($context, $this->id(), $this->downtimeClass());
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** Online: a catalog change, no table lock. The risk is compatibility and rollback — the level. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        $addition = EnumValueAddition::of($statement);

        if (! $addition instanceof EnumValueAddition) {
            return null;
        }

        // A value added to a type born in this migration is undone by the down() that
        // drops the type — nothing to roll back, no live consumers.
        if ($statement->migration->createsEnumType($addition->type)) {
            return null;
        }

        return 'ALTER TYPE … ADD VALUE has two catches on PostgreSQL 18: the new value cannot be used '
            .'in the same transaction it is added in, and the step is irreversible — a down() cannot '
            .'remove an enum value, so this migration cannot be cleanly rolled back. Consider whether '
            .'a lookup table would serve better than an enum for a value set that changes.';
    }
}
