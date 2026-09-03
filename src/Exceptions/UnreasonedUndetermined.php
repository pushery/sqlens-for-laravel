<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use LogicException;

/**
 * Something tried to answer "undetermined" without saying why.
 *
 * A skip without a reason is this package's own definition of a bug: it is indistinguishable from a
 * clean result to everything downstream, and in an agent loop it is read as "nothing to do here".
 * The rule is old; what is new is that it cannot be forgotten — the only way to build an
 * undetermined answer demands the reason, and this is what happens when somebody passes an empty
 * one.
 *
 * A `LogicException` rather than a runtime one on purpose: this is never a state a database, a file
 * or a user can produce. It is a tool that was written wrong.
 */
final class UnreasonedUndetermined extends LogicException
{
    public function __construct()
    {
        parent::__construct(
            'An undetermined answer needs a reason. A skip nobody explained is indistinguishable '
            .'from a clean result, and an agent reads it as "nothing to do here".'
        );
    }
}
