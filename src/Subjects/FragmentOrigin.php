<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * Where a raw-SQL fragment's text came from, syntactically. Raw material for the
 * injection rules — not a data-flow analysis (no taint), just the observable
 * shape at the callsite.
 */
enum FragmentOrigin: string
{
    case Literal = 'literal';
    case Concatenation = 'concatenation';
    case Interpolation = 'interpolation';
    case UnknownVariable = 'unknown_variable';
}
