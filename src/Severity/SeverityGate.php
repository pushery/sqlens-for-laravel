<?php

declare(strict_types=1);

namespace Pushery\SQLens\Severity;

use Pushery\SQLens\Findings\Finding;

/**
 * The risk gate: does this finding's severity reach the floor the project set?
 *
 * ## Why risk needs a gate of its own
 *
 * Levels model a strictness APPETITE — how pedantic a project wants SQLens to be, turned up over
 * time like a Larastan level. Severity models RISK, which is not a matter of appetite: a password
 * literal in a migration is critical whether or not the project has got round to level 5. Measured
 * against the level, such a finding would be invisible in exactly the projects most likely to have
 * it, because a project early in its adoption runs a low level.
 *
 * So the two are orthogonal, and this class is the second axis. It holds one rule and holds it in
 * one place: a finding blocks when its severity is at or above the configured floor.
 *
 * ## An unset floor is OFF, not zero
 *
 * `null` means the project named no floor, and then nothing breaches this gate — the findings are
 * still reported, they just do not decide the exit code. That is a different thing from a floor of
 * `Info`, which would make every informational security finding fail a build. The distinction
 * matters because "we have not decided yet" is the state a project starts in, and starting in
 * "everything blocks" is how a gate gets switched off wholesale.
 *
 * ## Primum non nocere
 *
 * Pure in-memory evaluation of findings that already exist: no connection, no lock, no write. The
 * gate cannot harm a database because it never touches one.
 */
final readonly class SeverityGate
{
    public function __construct(
        /** The floor a finding must reach to block, or null when the project set none. */
        public ?Severity $threshold = null,
    ) {}

    /**
     * Whether this finding breaches the risk gate.
     *
     * Deliberately indifferent to the finding's CATEGORY. Which axis a finding belongs to is
     * decided once, by {@see GateAxis::forCategory()}, and asking that question again here would be
     * the second place the answer lives — the shape of drift that lets a non-security rule slip
     * past the level gate through a severity nobody expected it to carry.
     */
    public function blocks(Finding $finding): bool
    {
        return $this->threshold instanceof Severity
            && $finding->severity instanceof Severity
            && $finding->severity->isAtLeast($this->threshold);
    }
}
