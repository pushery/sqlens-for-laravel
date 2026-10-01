<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\DowntimeUndetermined;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * A marker a rule adds when its findings' downtime class is DERIVED per statement rather than
 * fixed for the rule.
 *
 * {@see Rule::downtimeClass()} is one value for the whole rule, and for most rules that is exactly
 * right: `PG.L2.INDEX_NOT_CONCURRENT` blocks, always, whatever it is looking at. But a rule keyed
 * on a data table — MySQL's online-DDL matrix is the case this exists for — cannot answer that way.
 * The matrix answers per OPERATION and per SERVER VERSION, so two statements a single rule flags
 * can legitimately carry different classes, and one constant would have to be wrong about one of
 * them.
 *
 * A rule that does not implement this is untouched: the collector keeps stamping its constant. That
 * is the whole reason this is a marker rather than a method added to the Rule contract — a
 * capability a few rules have should not become a question every rule has to answer.
 *
 * ## Three answers, and none of them a default
 *
 * A class is the class. A {@see DowntimeUndetermined} says the class of THIS statement could not
 * be determined, and why: the collector stamps it on the finding, and the report counts it. Null
 * says the rule makes no claim about this statement, and the finding carries neither.
 *
 * None of them means "fall back to something reasonable". A rule whose data source could not
 * classify the operation says so with the undetermined and its reason; returning null there, or a
 * class that sounds harmless, would be the silent green this package refuses, arrived at through a
 * nicer-looking door.
 */
interface DerivesDowntimeClass
{
    /**
     * The downtime class for this specific statement, the undetermined when it cannot be named, or
     * null when the rule makes no claim about this statement.
     *
     * Called by the collector INSTEAD of {@see Rule::downtimeClass()} for a rule that implements
     * this — never in addition, so there is exactly one answer per finding and no question of
     * which of two wins.
     */
    public function downtimeClassFor(MigrationStatementView $statement): DowntimeClass|DowntimeUndetermined|null;
}
