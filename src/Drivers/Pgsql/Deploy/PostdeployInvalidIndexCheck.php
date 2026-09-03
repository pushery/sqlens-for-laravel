<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Pushery\SQLens\Catalog\Activity\ActivityRequest;
use Pushery\SQLens\Contracts\ActivityReader;
use Pushery\SQLens\Contracts\PostdeployCheck;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;
use Pushery\SQLens\Deploy\PendingWork;
use Pushery\SQLens\Deploy\PostdeployContext;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Throwable;

/**
 * The same INVALID-index reading, taken after the deploy instead of before it.
 *
 * ## It adapts rather than reimplements, and that is the point
 *
 * {@see InvalidIndexCheck} owns the catalog query, the `pg_depend` exclusion, the partition dedupe
 * and the finding identity. This class calls it. A second implementation over the same catalog state
 * would let one command report what the other did not — the same database answering differently
 * depending on which command asked, which is the determinism break this package treats as a defect
 * rather than an inconsistency.
 *
 * The finding IDs are therefore identical across `sqlens:predeploy` and `sqlens:postdeploy` by
 * construction, and `tests/Postgres/PostdeployInvalidIndexTest.php` compares two real runs to keep
 * it that way.
 *
 * ## The one intervention: a build that is still running
 *
 * `indisvalid = false` is LEGITIMATE while a `CREATE INDEX CONCURRENTLY` is in flight — and
 * immediately after `migrate --force` that is the realistic case, not the exotic one. A deploy that
 * kicked off a concurrent build would otherwise be told, seconds later, that it left wreckage behind.
 *
 * So the activity views are consulted for a build running against the same relation, and a finding
 * that collides with one is downgraded to `undetermined` with the reason named. Downgraded, never
 * dropped: "an index is invalid and something is still building it" is a real state somebody may
 * want to look at again in a minute, and silence would end that conversation.
 *
 * ## Why the downgrade cannot quietly become a pass
 *
 * Three things stop the check from answering: a running build, activity views that cannot be read,
 * and a catalog that cannot be read. All three are `undetermined` with their own reason, and none
 * of them is a `pass` — the difference between "no invalid index" and "could not tell" is the whole
 * value of running this after a deploy at all.
 */
final readonly class PostdeployInvalidIndexCheck implements PostdeployCheck, ProducesDebt
{
    /**
     * An INVALID index is a debt: it sits there until somebody drops it, and nothing about the
     * passage of time makes it go away.
     *
     * The half of this question worth building. The other half — a STATIC rule
     * reporting `CREATE INDEX CONCURRENTLY` in a migration as debt — would contradict the package's
     * own advice: `PG.L2.INDEX_NOT_CONCURRENT` calls `CONCURRENTLY` "the safe form" and asks for it
     * by name. A rule flagging the recommended shape is a false-positive machine that also argues
     * with its neighbor.
     *
     * What is real is the wreckage: an index left `indisvalid = false` by a run that did not finish.
     * That is a fact in `pg_index`, it blocks the next `CREATE INDEX` of the same name, and until
     * now it was reported on every run with no date and no way to say "known, next window".
     */
    public function debtKind(): string
    {
        return InvalidIndexCheck::DEBT_KIND;
    }

    /**
     * The index this finding leaves behind, read from the finding's own object identity.
     *
     * Only the plain finding reaches here at all: the registrar matches a finding to its claimant by
     * ID, and this class answers for `DEPLOY.LEGACY.INVALID_INDEX`. The name-collision finding
     * carries a different id and is therefore never claimed — which is the right answer rather than
     * an accident. That one reports a deploy that will STOP at a named statement; making it
     * acknowledgeable would let a team silence a blocker instead of clearing it.
     */
    public function debtReference(Finding $finding): ?string
    {
        return $finding->location->objectName;
    }

    /**
     * @param  PreflightCheck  $inner  the CONTRACT, not the class: {@see InvalidIndexCheck} is
     *                                 `final readonly` and cannot be doubled, and the attempt fails
     *                                 as a COMPILE error — an empty log, exit 1, zero reported
     *                                 failures. The default is still the real check, so nothing at
     *                                 a call site changes.
     */
    public function __construct(private PreflightCheck $inner = new InvalidIndexCheck) {}

    public function id(): string
    {
        return InvalidIndexCheck::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $this->inner->appliesTo($driver);
    }

    public function run(PostdeployContext $context): CheckResult
    {
        $result = $this->inner->run($this->asPreflight($context));

        if ($result->outcome !== Outcome::Fail) {
            // A pass stays a pass and an `undetermined` keeps the reason the inner check gave it.
            // Only a FINDING can be wrong for the post-deploy moment, so only a finding is examined.
            return $result;
        }

        if (! $context->activity instanceof ActivityReader) {
            return CheckResult::undetermined(
                $this->id(),
                'invalid_index_found_but_builds_unverifiable: '.count($result->findings).' index(es) '
                .'report `indisvalid = false`, and this run has no activity reader — so whether a '
                .'`CREATE INDEX CONCURRENTLY` is STILL BUILDING them could not be established. '
                .'Immediately after a deploy that is the likely explanation, and reporting wreckage '
                .'here would be wrong more often than right.',
                $result->findings,
            );
        }

        try {
            $building = $this->relationsUnderBuild($context->activity);
        } catch (Throwable $failure) {
            return CheckResult::undetermined(
                $this->id(),
                'activity_unreadable: '.count($result->findings).' index(es) report '
                .'`indisvalid = false`, and the activity views could not be read, so a build still '
                .'in flight could not be ruled out: '.$failure->getMessage(),
                $result->findings,
            );
        }

        if ($building === []) {
            // Nothing is building anything. The finding stands, and this is the state the whole
            // check exists for: the deploy has finished and left an index nobody is completing.
            return $result;
        }

        return CheckResult::undetermined(
            $this->id(),
            'index_build_in_progress: a `CREATE INDEX CONCURRENTLY` is still running against '
            .implode(', ', $building).', and an index under construction reports '
            .'`indisvalid = false` legitimately. The finding is held rather than dropped — check '
            .'again once the build finishes, because the same reading will mean the opposite then.',
            $result->findings,
        );
    }

    /**
     * The relations a concurrent index build is currently running against.
     *
     * @return list<string>
     */
    private function relationsUnderBuild(ActivityReader $activity): array
    {
        $relations = [];

        foreach ($activity->read(new ActivityRequest)->longRunningSessions as $session) {
            $relation = $session->relation;

            if ($relation !== null && $relation !== '') {
                $relations[] = $relation;
            }
        }

        // Sorted and deduplicated: the reason travels into a report that must be byte-identical
        // across two runs over an unchanged instance.
        $relations = array_values(array_unique($relations));
        sort($relations);

        return $relations;
    }

    /**
     * The inner check's world, built from this one.
     *
     * The pending set is EMPTY here and that is correct rather than convenient: after
     * `migrate --force` nothing is pending, and this check never consults it — it asks the catalog
     * what exists, not what is about to. An adapter may only wrap a check for which both halves of
     * that sentence are true.
     */
    private function asPreflight(PostdeployContext $context): PreflightContext
    {
        return new PreflightContext(
            connection: $context->connection,
            driver: $context->driver,
            serverVersion: $context->serverVersion,
            session: $context->session,
            pending: new PendingWork,
            profile: $context->profile,
            deadlineAt: hrtime(true) + ($context->remainingBudgetMs() * 1_000_000),
            activity: $context->activity,
        );
    }
}
