<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

/** Which of the two readings a statement is about. */
enum DriftSide: string
{
    /** The database as it is right now. */
    case Live = 'live';

    /** What the migrations, replayed, say it should be. */
    case Expected = 'expected';
}
