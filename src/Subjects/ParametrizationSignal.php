<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * A three-valued, purely syntactic observation about a raw-SQL fragment. It is
 * explicitly NOT "safe/unsafe": that would be a taint judgment, and taint
 * analysis is a sealed rabbit hole. A fragment of unknown origin is
 * Undetermined, never silently Parametrized — no silent green.
 */
enum ParametrizationSignal: string
{
    case Parametrized = 'parametrized';
    case Interpolated = 'interpolated';
    case Undetermined = 'undetermined';
}
