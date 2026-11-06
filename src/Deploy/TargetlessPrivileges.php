<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Capture\CapturedStatement;

/**
 * What a driver knows about the statements its classifier recognizes and keeps without a target.
 *
 * A session setting, a comment and a row security policy are recognized and carry no target on
 * purpose: the classifier does not invent an object for a statement that names none, and the
 * statement that changes a column is the `ALTER TABLE` beside its comment. What such a statement
 * asks of the migration role is a question about the engine, so the driver answers it, and
 * {@see RequiredPrivileges} asks rather than guessing.
 *
 * Three answers, kept apart on purpose:
 *
 * - an empty list: the statement needs no privilege of its own, as a session setting any role may
 *   make for its own session;
 * - requirements: the object and the right the statement needs, named the way a target names it;
 * - `null`: the driver cannot tell, and the derivation reports the statement as underivable.
 */
interface TargetlessPrivileges
{
    /**
     * What the role must be allowed to do for a statement the classifier keeps without a target.
     *
     * @return list<PrivilegeRequirement>|null
     */
    public function requirementsOf(CapturedStatement $statement): ?array;
}
