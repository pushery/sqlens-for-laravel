<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * The prefix every deploy-lifecycle check reports under.
 *
 * ## The defect this replaces
 *
 * All of them wrote `sqlens.predeploy`, as a literal, in fifteen places — and the same checks run
 * from `sqlens:postdeploy`. Measured on a real run:
 *
 *     [fail]  DEPLOY.LEGACY.CONSTRAINT_NOT_VALIDATED  sqlens.predeploy  level=0  …
 *
 * printed by `sqlens:postdeploy`. A reader who takes that line at face value and goes looking in
 * the pre-deploy log finds nothing, because the check never ran there.
 *
 * ## Why the fix is a NEUTRAL name rather than a per-command one
 *
 * What `messagePrefix` fundamentally is — a translation namespace or a statement of provenance —
 * is genuinely unsettled, and settling it depends on a decision this package has not made — whether
 * finding messages are localized at all. Both readings are live, and they pull in opposite
 * directions: a
 * namespace must NOT vary per command, or one message needs translating twice and the two
 * commands stop reporting the same finding; a provenance statement must vary, or it lies.
 *
 * A name that names the SUBJECT rather than the command is correct under both. `sqlens.deploy` is
 * one namespace, so the identity the anti-duplicate arm depends on survives; and it claims nothing
 * about which command looked, so it cannot be wrong about that either.
 *
 * This is not a new idea here — {@see DebtNotice::MESSAGE_PREFIX} reached the same place for the
 * same reason and said so: "a finding about the account should not claim to come from a command
 * that merely looked". This constant applies that resolution to the checks it was written beside.
 *
 * One constant rather than fifteen literals is the other half. A literal repeated fifteen times is
 * a decision nobody can revisit in one place, and it is how this one survived being wrong.
 */
final readonly class DeployNotice
{
    /**
     * The subject, never the command.
     *
     * `sqlens.deploy` — not `sqlens.predeploy`, not `sqlens.postdeploy`. The checks belong to the
     * deploy lifecycle, and both commands run the same ones.
     */
    public const string MESSAGE_PREFIX = 'sqlens.deploy';
}
