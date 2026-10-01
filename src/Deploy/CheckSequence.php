<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Closure;
use Pushery\SQLens\Catalog\UnsealedReaderSession;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * The one implementation of "run a list of checks under a budget and report what happened".
 *
 * ## Why this is extracted rather than written twice
 *
 * Preflight and postdeploy ask about different worlds, but they SEQUENCE their checks identically:
 * declared order, `appliesTo()` before `run()`, a budget consulted before each one, and a check the
 * budget stopped reported as `undetermined` rather than omitted.
 *
 * Written twice, those four rules would drift — and the drift would be invisible, because each copy
 * would keep passing its own tests. The one that matters most is the last: the day one runner
 * started omitting budget-stopped checks instead of reporting them, its reports would read cleaner
 * than the other's while meaning less. That is the silent green this package exists to refuse, so
 * the rule lives in one place where a change to it is a change to both.
 *
 * The differing halves — what a check is, and what it is run against — arrive as closures. This
 * class never sees a driver, a context or a connection.
 */
final readonly class CheckSequence
{
    /**
     * The handle is the check's POSITION, never its id.
     *
     * Measured, on the version that keyed by id: `DEPLOY.PREFLIGHT.MISSING_PRIVILEGE` is carried by
     * the PostgreSQL grant check AND its MySQL twin — deliberately, because it is one question. A
     * map keyed by id collapsed them to whichever was registered last, so on PostgreSQL the
     * surviving entry answered `appliesTo('pgsql') === false` and the grant check simply never ran.
     * It was then listed as NOT APPLICABLE, which reads like a decision rather than a loss.
     *
     * The whole suite stayed green. Two checks may share an id — the driver is what tells them
     * apart — so position is the only handle that cannot silently drop one.
     *
     * @param  list<string>  $ids  the checks' ids, in the order they will run, indexed by position
     * @param  Closure(int): bool  $applies  whether the check at that position has anything to say
     * @param  Closure(): bool  $exhausted  whether the budget is spent, asked fresh before each one
     * @param  Closure(int): CheckResult  $execute
     * @param  Closure(): ?UnsealedReaderSession  $refused  the refusal that ended the reader session, asked
     *                                                      after each check and before the next one
     */
    public static function run(array $ids, Closure $applies, Closure $exhausted, Closure $execute, ?Closure $refused = null): PreflightReport
    {
        $refused ??= static fn (): ?UnsealedReaderSession => null;

        $results = [];
        $notApplicable = [];

        // Per check, not one total. A budget that breaks tells you the run is too slow; the
        // per-check split tells you WHICH check made it so — and without that, the first response
        // to a broken budget is to raise the number, because nobody can see what to fix.
        $timings = [];

        foreach ($ids as $position => $id) {
            if (! $applies($position)) {
                $notApplicable[] = $id;

                continue;
            }

            // A session that could not prove its seal stays refused, and a check that still asked would
            // only be refused again. Named here rather than left to each check, which would report the
            // refusal as an ordinary catalog read failure.
            $refusal = $refused();

            if ($refusal instanceof UnsealedReaderSession) {
                $results[] = self::unsealed($id, $refusal);

                continue;
            }

            // Asked before each one rather than once at the top: the budget is spent BY the checks,
            // so the only reading that means anything is the one taken now.
            if ($exhausted()) {
                $results[] = CheckResult::undetermined(
                    $id,
                    UndeterminedReason::RunTimeBudgetExhausted,
                    'the run reached its time budget before this check started, so it never asked. '
                    .'Reported rather than omitted: a gate that quietly ran half its checks and '
                    .'answered clean would be trusted like a complete one.',
                );

                continue;
            }

            $startedAt = hrtime(true);
            $result = $execute($position);
            $timings[$id] = (int) round((hrtime(true) - $startedAt) / 1_000_000);

            // The check whose read was refused caught the refusal as a failed read, the way it catches
            // any. Its answer is the refusal's, with whatever it found before it.
            $refusal = $refused();
            $results[] = $refusal instanceof UnsealedReaderSession
                ? self::unsealed($id, $refusal, $result->findings)
                : $result;
        }

        return new PreflightReport($results, $notApplicable, $timings);
    }

    /** @param  list<Finding>  $findings */
    private static function unsealed(string $id, UnsealedReaderSession $refusal, array $findings = []): CheckResult
    {
        return CheckResult::undetermined(
            $id,
            UndeterminedReason::ReaderSessionUnsealed,
            'the reader session could not prove it is read-only, so this check did not read, and the '
            .'session is not probed again: '.$refusal->getMessage(),
            $findings,
        );
    }
}
