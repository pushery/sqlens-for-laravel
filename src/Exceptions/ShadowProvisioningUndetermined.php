<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use Pushery\SQLens\Findings\UndeterminedReason;
use RuntimeException;

/**
 * A shadow provisioner met a precondition that stops the run BEFORE any database
 * is created — the role cannot create a database, the template is in use, or the
 * generated name already exists.
 *
 * It is thrown, not returned, because `ShadowProvisioner::provision()` returns a
 * live `ShadowSession` on success and there is no half-session to hand back when
 * provisioning cannot even begin. The `ShadowCaptor` catches exactly this type
 * around the provision step and turns it into an all-undetermined run carrying the
 * named `reason`, so the precondition becomes a clear result the user can act on —
 * never a passed-through permission error and never a silent pass. Any OTHER
 * throwable from provisioning stays a genuine failure.
 *
 * This is distinct from the guard and probe checks the captor makes itself: those
 * are engine-neutral and decided before a provisioner is reached; these are the
 * engine-specific preconditions only the provisioner can see, so the provisioner
 * raises them and the captor maps them through this one carrier.
 *
 * ## Why `$detail` cannot break determinism, which is not obvious and was nearly a redesign
 *
 * The detail is free text — a pid, a timestamp — and this package compares its agent artifacts
 * BYTE FOR BYTE. That reads like a collision, and the first attempt at this diagnosis stopped
 * here and proposed giving `CaptureResult` a detail field with the determinism tests excluding
 * it again.
 *
 * It is not a collision, and the reason is one line of the catch site: `ShadowCaptor` maps this
 * exception with `allUndetermined($pending, $section, $undetermined->reason)` — the REASON ENUM
 * and nothing else. The message is discarded there by construction, so no result, no reporter
 * and no artifact can ever observe it. What can observe it is a reader: a failing test, a log,
 * a caller that lets it propagate.
 *
 * That is the whole design. The deterministic channel carries the enum; the human channel
 * carries the enum PLUS who was in the way. Neither can leak into the other, so neither has to
 * be weakened for the other's sake — and nothing needed to be excluded from a comparison.
 *
 * The corollary is a constraint on what may go in here: whatever a log or a CI transcript may
 * hold, this may hold. A running statement's TEXT may not (see
 * the maintenance gateway's `describeActiveConnections()` carries that reasoning).
 *
 * That reference is deliberately PROSE rather than a `{@see}` with a class name. This namespace is
 * held to the A→C split by an architecture arm — `Exceptions` may not reach a driver — and a
 * fully-qualified `{@see}` does not stay a comment: the formatter rewrites it into a real `use`
 * statement, which is exactly what the arm forbids. Measured, in the pull request that added this
 * paragraph: the import appeared without being typed, and the arm went red on a docblock.
 */
final class ShadowProvisioningUndetermined extends RuntimeException
{
    /**
     * @param  string|null  $detail  diagnosis for a human reading this exception — never for a
     *                               machine reading a result
     */
    public function __construct(public readonly UndeterminedReason $reason, public readonly ?string $detail = null)
    {
        parent::__construct($detail === null ? $reason->description() : $reason->description().' '.$detail);
    }
}
