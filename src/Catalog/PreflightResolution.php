<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Contracts\StatisticsReader;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * Everything a preflight run needs from the connection layer, resolved once.
 *
 * ## Why this is a type and not a tuple
 *
 * It was a five-element list, destructured positionally at its one call site, and it was already at
 * the edge of what that can carry honestly: `[$session, $skip, $advisory, $driver, $version]` has
 * two nullable skips in it that mean different things, and swapping them at the destructuring end
 * produces working code that reports the wrong reason. Adding the readers would have made it seven.
 *
 * Naming the fields removes a whole class of silent mistake, and it also removes the pressure to
 * skip one: a positional list gets shorter when somebody decides a value is "not that important".
 *
 * ## Why the readers are RESOLVED here rather than looked up in the checks
 *
 * A check that built its own reader would need a `Connection`, and the console that hands the
 * context down may not name one — the core-purity census pins exactly three files that know both
 * engines, and `PredeployCommand` is not among them. Resolving here keeps that true while giving
 * every check the readers it needs.
 *
 * Resolved, not RUN. Nothing here reads anything beyond the server identity the version needs: a
 * context build that already queried would move cost into a step the time budget does not measure,
 * which is how a budget quietly stops being one.
 */
final readonly class PreflightResolution
{
    private function __construct(
        /** The sealed session, or null when the run cannot happen at all. */
        public ?ReaderSession $session,
        /** Why the run cannot happen, or null when it can. */
        public ?CatalogSkip $refusal,
        /**
         * A named concern that does NOT stop the run — currently: the preflight is reading through
         * the connection that runs the migrations, which works and costs the least-privilege claim.
         *
         * Deliberately a separate field from the refusal rather than the same one with a severity.
         * They are answered at different points and by different code, and one field would make
         * "did this run happen?" a question about a value's contents.
         */
        public ?CatalogSkip $advisory,
        public string $driver,
        public ?ServerVersion $serverVersion,
        /** How big the objects a finding names are, or null when this driver has no reader for it. */
        public ?StatisticsReader $statistics,
        /** What the instance is doing right now, or null when this driver has no reader for it. */
        public ?ActivityReader $activity,
        /**
         * The database ROLE the migrations run as, or null when the configuration does not say.
         *
         * Resolved here rather than by the check that needs it, for the reason every other field on
         * this object is: a check reaching for `config()` would be a second path to an answer this
         * layer already gives, and the two would drift.
         */
        public ?string $migrationRole = null,
    ) {}

    public static function refused(CatalogSkip $refusal, string $driver = ''): self
    {
        return new self(null, $refusal, null, $driver, null, null, null);
    }

    public static function resolved(
        ReaderSession $session,
        string $driver,
        ?ServerVersion $serverVersion,
        ?CatalogSkip $advisory = null,
        ?StatisticsReader $statistics = null,
        ?ActivityReader $activity = null,
        ?string $migrationRole = null,
    ): self {
        return new self($session, null, $advisory, $driver, $serverVersion, $statistics, $activity, $migrationRole);
    }
}
