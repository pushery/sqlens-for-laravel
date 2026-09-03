<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

/**
 * The direction a captured migration statement runs in. down() and data
 * migrations are invisible to pure .sql tools; this field is where SQLens
 * reasons about them.
 */
enum MigrationDirection: string
{
    case Up = 'up';
    case Down = 'down';
}
