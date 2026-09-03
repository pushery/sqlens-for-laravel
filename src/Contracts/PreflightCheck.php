<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\PreflightContext;

/**
 * One question the gate asks the target database immediately before a deploy.
 *
 * ## Three states, and the fourth one is deliberately impossible
 *
 * A check answers `pass`, `fail` or `undetermined`, and `undetermined` cannot be built without a
 * reason. There is no `skipped` and no `n/a` — not because they would be untidy, but because
 * `schema_version` makes the JSON a public contract from 1.0 on, and a fourth value would be an
 * undeclared one in it.
 *
 * The case those values would have covered is handled a rank higher instead: a check whose
 * {@see self::appliesTo()} excludes the running driver is never RUN, so it produces no result at
 * all. The report lists it from the registry as not applicable. That difference matters — "this
 * check did not apply to your database" and "this check could not answer" send a reader to two
 * different places, and one value for both would send them to neither.
 */
interface PreflightCheck
{
    /**
     * The stable identifier this check's findings carry.
     *
     * Public API from 1.0: a pipeline greps for it, a suppression names it, and a report from six
     * months ago has to still mean something.
     */
    public function id(): string;

    /**
     * Whether this check has anything to say about the given driver.
     *
     * Asked BEFORE the run rather than answered inside it. A check that ran and returned "not for
     * me" would have opened a session, spent budget and produced a result somebody has to classify;
     * asked here it costs nothing and the report can say plainly that it did not apply.
     */
    public function appliesTo(string $driver): bool;

    /** Ask the question. Everything the check may look at arrives in the context. */
    public function run(PreflightContext $context): CheckResult;
}
