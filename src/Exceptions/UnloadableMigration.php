<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * A migration file was read and did not yield a migration.
 *
 * It exists because the alternative is a `TypeError` naming a return type, and that sends the
 * reader into this package's source to work out that the subject is their own file. Measured in a
 * consuming project on 2026-09-05: `sqlens:lint --file=…` died with
 * `resolve(): Return value must be of type Migration, int returned` — true, useless, and about a
 * file the message never named.
 *
 * Whatever this package decides to support, a refusal says WHICH file and WHY.
 */
final class UnloadableMigration extends RuntimeException
{
    /**
     * The file neither returned a migration nor declared one this loader could find.
     *
     * Both shapes Laravel accepts are handled before this is reached — an anonymous class the file
     * RETURNS, and a named class it DECLARES. Reaching here means the file is a third thing: it
     * returns something that is not a migration and declares no class whose name matches its own,
     * so nothing in it can be run as a migration.
     */
    public static function yieldedNothing(string $file, string $returned): self
    {
        return new self(sprintf(
            'The migration file %s returned %s and declares no migration class matching its own '
            .'name, so there is nothing here to lint. Laravel accepts two shapes: a file that '
            .'RETURNS an anonymous class (`return new class extends Migration { … };`) and one '
            .'that DECLARES a named class whose name is the studly-cased file name after the '
            .'timestamp. This file is neither.',
            $file,
            $returned,
        ));
    }
}
