<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Exceptions\ShadowDatabaseKept;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * What building the expectation side produced: a catalog, or a named reason there is none.
 *
 * Three-valued by construction rather than by convention. A builder that returned
 * `?CatalogSnapshot` would hand the caller a null it has to interpret, and every caller would
 * interpret it as "nothing to compare" — which reads as "no drift" at the far end of the pipeline.
 * That is the silent green this package exists to refuse, arriving through a type rather than
 * through a bug.
 *
 * There is deliberately no `pass`/`fail` here. This object answers *could the expectation be built*,
 * never *do the two sides agree* — the comparison is {@see DriftComparator}'s, and a builder that
 * hinted at a verdict would be a second place where drift is decided.
 */
final readonly class ShadowReferenceOutcome
{
    /**
     * @param  list<string>  $keptDatabases  what `capture.shadow.keep_on_failure` left on the server
     * @param  string|null  $refusal  what a refused provisioning said beyond its reason, for a person:
     *                                it can differ from run to run, so no report carries it, and the
     *                                commands write it on STDERR
     * @param  list<string>  $notes  what setting up the throwaway database left out that a person
     *                               should know, written on STDERR for the same reason
     */
    private function __construct(
        public ?CatalogSnapshot $snapshot,
        public ?UndeterminedReason $reason,
        public ?string $shadowDatabase,
        public array $keptDatabases = [],
        public ?string $refusal = null,
        public array $notes = [],
    ) {}

    /**
     * The expectation catalog, and the throwaway database it was read from.
     *
     * The database name rides along because a report has to be able to say where the expectation
     * came from. It is already dropped by the time this object exists — naming it is provenance,
     * not an invitation to connect to it again.
     *
     * @param  list<string>  $notes  what setting up the throwaway database left out that a person should know
     */
    public static function of(CatalogSnapshot $snapshot, string $shadowDatabase, array $notes = []): self
    {
        return new self($snapshot, null, $shadowDatabase, notes: $notes);
    }

    /**
     * No expectation could be built, and this is why.
     *
     * @param  list<string>  $keptDatabases  the databases a failed replay left standing for inspection
     */
    public static function undetermined(UndeterminedReason $reason, array $keptDatabases = [], ?string $refusal = null): self
    {
        return new self(null, $reason, null, $keptDatabases, $refusal);
    }

    /**
     * Why there is no expectation, and which databases are still on the server when the run kept
     * them. The reason alone names none, and a person who asked for the databases to be kept needs
     * exactly that to find them.
     */
    public function describe(): string
    {
        $reason = (string) $this->reason?->value;

        return $this->keptDatabases === []
            ? $reason
            : $reason.'; '.UndeterminedReason::ShadowKeptOnFailure->value.': '.ShadowDatabaseKept::sentence($this->keptDatabases);
    }

    public function isUndetermined(): bool
    {
        return ! $this->snapshot instanceof CatalogSnapshot;
    }
}
