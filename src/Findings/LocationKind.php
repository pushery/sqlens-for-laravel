<?php

declare(strict_types=1);

namespace Pushery\SQLens\Findings;

/**
 * Which subject source a finding's location addresses. Mirrors the three subject
 * kinds but lives with the finding, since a location is reporter output.
 */
enum LocationKind: string
{
    case Migration = 'migration';
    case Catalog = 'catalog';
    case Callsite = 'callsite';
}
