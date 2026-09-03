<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Where a captured statement came from, as far as the run can honestly tell.
 *
 * Three cases, not two, and the third is the whole reason this is an enum rather than a boolean.
 *
 * A path-bound rule — one that means something different inside `database/migrations` than outside
 * it — has to answer three separate questions, and collapsing them loses the one that matters. A
 * password literal in a migration is a Critical finding. The identical literal in a seeder is test
 * data and must be silent, or the rule is switched off within a week for crying wolf. And a snippet
 * handed straight to the fast path has no file at all: the honest answer there is neither of the
 * first two.
 *
 * A boolean forces that third case into one of the other two, and both choices are wrong in a way
 * that is invisible. `false` means a real leak goes unreported. `true` means a Critical fires on a
 * suspicion — on evidence the run does not have.
 */
enum OriginBinding: string
{
    /**
     * The statement came from a file under a registered migration path.
     *
     * "Registered" means the migrator says so — `database/migrations` plus every path a package
     * added through `loadMigrationsFrom()`. A tenant setup nesting migrations in subdirectories is
     * covered by the same answer, because a subdirectory of a registered path is still under it.
     */
    case Migration = 'migration';

    /**
     * The statement came from a file that is NOT a migration: a seeder, a factory, a test fixture.
     *
     * The distinction is made on the REGISTRATION, never on the file name. A seeder called
     * `2026_01_01_000000_seed_users.php` is still a seeder, and a migration inside
     * `database/migrations/tenant/` is still a migration.
     */
    case NotAMigration = 'not-a-migration';

    /**
     * The run cannot tell — most often because there is no file: `--file` pointed at a snippet, or
     * the statement arrived through a path that carries no provenance.
     *
     * A path-bound rule answers `undetermined` here with the reason
     * {@see UndeterminedReason::OriginUnknown}. Never a silent pass, and
     * never a Critical on suspicion.
     */
    case Unknown = 'unknown';
}
