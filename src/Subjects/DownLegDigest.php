<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * What a migration's `down()` would EMIT — the canonical statements of the rollback leg,
 * captured but never executed, or a named reason why they could not be read.
 *
 * {@see DownMethodState} answers whether there is a rollback path at all; this answers what
 * that path DOES. Two questions, two types, on purpose: a migration can have a perfectly
 * present `down()` whose statements destroy far more than `up()` ever built, and a state
 * enum has no room to say so.
 *
 * ## Why the statements come from a capture and not from the file
 *
 * The pre-scan already parses every migration, so reading `down()` off the AST would cost
 * nothing extra — and it would be a SECOND reading of what a migration does, beside the
 * canonical one every rule uses. Those two readings would drift, and the AST one would have
 * to re-derive by hand what the canonicalization already knows: which table a
 * `dropColumn()` inside a `Schema::table()` closure belongs to, what Laravel's grammar
 * turns `dropConstrainedForeignId()` into, that `dropSoftDeletes()` is a column drop. The
 * capture answers all of it because it asks the framework instead of guessing at it.
 *
 * ## Reading it is never RUNNING it
 *
 * The leg is captured under Laravel's pretend mode — always, in every capture mode,
 * including shadow. A rollback that is merely being linted must not run: `down()` is the
 * one migration method whose whole job is to destroy things. The statements are what it
 * WOULD emit, which is exactly what a rule about `down()` needs and the only thing primum
 * non nocere permits it to take.
 *
 * ## The unreadable case is a first-class value, not an empty list
 *
 * A leg whose statements could not be canonicalized has to be distinguishable from a leg
 * that emits nothing — otherwise a rollback SQLens could not read would report as a
 * rollback that destroys nothing, which is the silent green the whole three-valued model
 * exists to prevent.
 */
final readonly class DownLegDigest
{
    /**
     * @param  list<MigrationStatementDigest>  $statements  the rollback leg's canonical statements, in capture order
     * @param  UndeterminedReason|null  $unreadableReason  set exactly when the leg could not be read
     */
    private function __construct(
        public array $statements,
        public ?UndeterminedReason $unreadableReason,
    ) {}

    /**
     * A leg that was read. An EMPTY list is a real answer and means the rollback emits no
     * SQL — a `down()` that is absent, empty, or throws before its first statement.
     *
     * @param  list<MigrationStatementDigest>  $statements
     */
    public static function of(array $statements): self
    {
        return new self($statements, null);
    }

    /**
     * A leg that could not be read, with the reason a finding will carry.
     *
     * The reason is the value, not a boolean beside it: a rule that learned only THAT the leg
     * was unreadable would have to invent a reason at the point of use, and an invented reason
     * points a reader at the wrong file.
     */
    public static function unreadable(UndeterminedReason $reason): self
    {
        return new self([], $reason);
    }
}
