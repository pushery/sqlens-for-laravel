<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Pushery\SQLens\Contracts\PostdeployCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\PostdeployContext;

/**
 * A check that answers NOT APPLICABLE, out loud, and that is its entire job.
 *
 * ## Why a class exists for something MySQL cannot have
 *
 * `sqlens:postdeploy` on PostgreSQL reports `DEPLOY.LEGACY.INVALID_INDEX` — an index left behind by
 * a `CREATE INDEX CONCURRENTLY` that did not finish. InnoDB has no such state: an index build is
 * either committed or rolled back, and there is no catalog flag equivalent to `indisvalid = false`.
 *
 * The tempting shape is therefore no class at all. That is exactly the silent green this package
 * refuses. A user who read the PostgreSQL documentation, ran the same command against MySQL and saw
 * nothing has been told two things at once — "there is no wreckage" and "this question was never
 * asked" — and the report gives no way to tell which. On the engine where somebody is MOST likely to
 * be comparing two databases, that is the worst place to leave the distinction unmade.
 *
 * So the check runs, answers `undetermined`, and names the reason. It costs one line in the report
 * and removes a question the reader would otherwise have to answer by reading source.
 *
 * ## It points at the nearest thing that IS real
 *
 * "Not applicable" on its own is a shrug. What corresponds functionally on this engine is the
 * temporary table an `ALGORITHM=COPY` rebuild leaves behind when it dies — `#sql-1234_a` — and that
 * is what {@see OrphanTransitionObjectCheck} finds. The reason says so, so a reader who came looking
 * for abandoned-build wreckage leaves with the id that has it.
 *
 * ## It reads nothing
 *
 * No query, no session, no privilege. The answer is a property of the engine rather than of the
 * instance, so asking the server would be theatre — and a check that queried to prove a constant
 * would be one more thing to fail on a managed database for no benefit.
 */
final readonly class InvalidIndexCheck implements PostdeployCheck
{
    public const string ID = 'DEPLOY.LEGACY.INVALID_INDEX';

    public function id(): string
    {
        return self::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $driver === 'mysql';
    }

    public function run(PostdeployContext $context): CheckResult
    {
        return CheckResult::undetermined(
            self::ID,
            'not applicable on this driver: InnoDB has no invalid-index state — an index build is '
            .'either committed or rolled back, and there is no equivalent of PostgreSQL\'s '
            .'`indisvalid = false`. This is reported rather than skipped so that a reader comparing '
            .'two databases can tell "no wreckage" from "never asked". The functionally nearest case '
            .'on MySQL is the temporary table an ALGORITHM=COPY rebuild leaves behind when it dies, '
            .'which DEPLOY.LEGACY.OSC_ARTIFACT reports.',
        );
    }
}
