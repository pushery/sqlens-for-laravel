<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * Where the end-of-life data a run judged from actually came from.
 *
 * Three files can answer the same question, and they are searched in a fixed order: a path the
 * project configured, the copy an application published into its own `resources/`, and the copy
 * bundled with the package. That order is the whole point of the type — an operator who refreshed
 * the data and still sees the old verdict needs to know WHICH file was read, and "somewhere" is not
 * an answer they can act on.
 *
 * It travels into the reproducibility header for the same reason a server version does: two runs
 * that disagree are only debuggable if each says what it read.
 */
enum EolSource: string
{
    /** `sqlens.security.advisories.path` — an explicit choice, so it beats both others. */
    case Configured = 'configured';

    /** The application's own published copy, under its `resources/`. */
    case Published = 'published';

    /** The copy that shipped with the package. Always present, and therefore the floor. */
    case Bundled = 'bundled';
}
