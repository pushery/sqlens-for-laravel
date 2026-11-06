<?php

declare(strict_types=1);

namespace Pushery\SQLens\Patterns;

/** What {@see IndexAdvisor} answers for a query pattern. */
enum IndexAdviceStatus: string
{
    /** An index that serves the pattern does not exist yet; the advice carries its DDL. */
    case Suggested = 'suggested';

    /** An index on the table already serves the pattern; the advice names it. */
    case Covered = 'covered';

    /** The answer would be a guess; the advice says why. */
    case Undetermined = 'undetermined';
}
