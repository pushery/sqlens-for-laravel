<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Contracts\CatalogReader;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * One comparison of a live schema against what the migrations say it should be — the ONE path.
 *
 * ## Why this is a class and not a method on the command that had it first
 *
 * `sqlens:drift` owned this sequence, and `sqlens:postdeploy --expect-shadow` needs exactly the same
 * one. Two commands answering "does this database match its migrations" from two code paths would
 * be free to disagree — and would, the first time somebody fixed a normalization in one of them.
 * That is not a hypothetical failure mode in this package: it is the one the fast-path rule exists
 * to prevent, stated as "two code paths for fast and correct are forbidden".
 *
 * So the sequence lives here once. What the two commands still own is everything AROUND it: their
 * own options, their own exit codes, their own report shapes, and — crucially — their own decision
 * about whether to run it at all.
 *
 * ## What it does NOT do
 *
 * It does not decide the guard, resolve the pending migrations, apply excludes, or write anything.
 * The guard decision arrives as a value, because deciding it needs an interactive prompt that a
 * service has no business owning; the excludes are applied by the caller, because `sqlens:drift`
 * also has a `--update-excludes` mode where they must NOT be applied.
 *
 * What it does own is the ordering — reference first, live second, compare — and the one property
 * that ordering carries: the live reading happens AFTER the shadow replay, so a schema that changed
 * during the replay is compared as it is now rather than as it was before.
 */
final readonly class ExpectationComparison
{
    public function __construct(private ShadowReferenceBuilder $builder) {}

    /**
     * @param  iterable<PendingMigration>  $migrations  the migrations the expectation replays
     * @param  CatalogReader  $live  the reader for the database as it IS
     */
    public function run(
        GuardDecision $decision,
        iterable $migrations,
        CatalogRequest $request,
        SubjectContext $context,
        CatalogReader $live,
    ): ExpectationComparisonOutcome {
        $reference = $this->builder->build($decision, $migrations, $request, $context);

        // No expectation, no comparison — and NOT an empty one. A run that could not build the
        // reference has established nothing about the live database, so the named reason travels
        // out rather than a reassuring empty report.
        if (! $reference->snapshot instanceof CatalogSnapshot) {
            return ExpectationComparisonOutcome::unavailable($reference);
        }

        return ExpectationComparisonOutcome::compared(
            new DriftComparator()->compare($live->read($request), $reference->snapshot),
            $reference,
        );
    }
}
