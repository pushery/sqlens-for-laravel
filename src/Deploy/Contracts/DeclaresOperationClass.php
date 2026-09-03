<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Contracts;

use Pushery\SQLens\Deploy\SeverityEscalator;

/**
 * A rule declaring WHICH KIND of operation its findings are about.
 *
 * The severity escalator weighs a finding against the size of the object it names, and the same size
 * means different things for different operations: a gigabyte is a long rewrite and nothing at all
 * to a constraint validation, while a hundred thousand rows is unremarkable for an index and the
 * line at which a backfill belongs in a queued job. So the escalator needs to know which kind it is
 * looking at before a number means anything.
 *
 * ## Why the RULE declares it and not the finding
 *
 * A finding carries a `ruleId`, not a rule — so the class has to be looked up, and the rule is the
 * only thing that knows. That is the same shape {@see ProducesDebt} already has, and it is
 * deliberately not a second convention: the registrar builds `ruleId => rule` from the rules that
 * ran and asks each finding's claimant.
 *
 * ## Why it is opt-in, and why silence must mean NOTHING
 *
 * Most rules do not judge an operation at all. A catalog rule reports a STATE — an unused index, a
 * database on the wrong charset — and there is no operation whose size could matter. A drop is not a
 * build: its danger is data loss, and escalating it by row count would hang the severity on an axis
 * that says nothing about it.
 *
 * So a rule that declares nothing gets no escalation, and that is an answer rather than a gap. A
 * registrar that GUESSED — from the level, from the id, from `downtime_class` — would give every
 * rule a class, the numbers would look plausible, and the threshold would sit on the wrong axis
 * silently.
 *
 * ## `downtime_class` is NOT this
 *
 * The temptation is real, because both look like "what kind of operation is this". They are
 * different axes: `downtime_class` says what an operation COSTS, this says what KIND it is, and two
 * operations with the same cost can be different kinds. `LockBlockerCheck` makes the same
 * distinction for lock modes and states the reason in the same words — the axis that answers cost
 * cannot answer identity.
 *
 * @see SeverityEscalator
 * @see resources/data/escalation-thresholds.json for the four classes and their measured lines
 */
interface DeclaresOperationClass
{
    /**
     * The operation this rule's findings describe.
     *
     * One of the classes the shipped threshold artifact names — `rewrite`, `index_build`,
     * `constraint_validation`, `backfill`. A class the artifact does not know is refused rather than
     * ignored: an unknown operation is a rule pointing at a threshold that does not exist, and the
     * escalation it expected would silently never happen.
     */
    public function operationClass(): string;
}
