<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\PostdeployContext;

/**
 * One question asked of the database immediately AFTER `migrate --force`.
 *
 * ## The moment is the whole difference
 *
 * A post-deploy check reads the same catalogs a preflight check reads, and means something else by
 * what it finds. An INVALID index before a deploy is wreckage from a previous attempt; the same
 * index afterwards is THIS deploy having stopped halfway. Same reading, two sentences, and the one
 * a reader needs depends only on when it was taken.
 *
 * That is why this is its own contract rather than a flag on {@see PreflightCheck}: a check has to
 * be written knowing which sentence it is producing, and a boolean passed in at runtime would let
 * one implementation produce both — including the wrong one.
 *
 * ## Three states, and no fourth
 *
 * `pass`, `fail`, `undetermined` — and `undetermined` cannot be constructed without a reason. There
 * is no `skipped`: a check whose {@see self::appliesTo()} excludes the running driver is never RUN
 * and appears in the report as not applicable, which is a different statement from "could not
 * answer" and belongs in a different place.
 *
 * ## What it must never do
 *
 * Read catalog and state views, nothing else. No user table, no `EXPLAIN`, no write, and never a
 * lock of its own — the deploy has just finished and the application is already live against it.
 */
interface PostdeployCheck
{
    /** The stable identifier this check's findings carry. Public API from 1.0 on. */
    public function id(): string;

    /**
     * Whether this check has anything to say about that driver.
     *
     * False means NOT RUN, not "passed" — the verifier records it as not applicable, so a
     * PostgreSQL-only check on MySQL never contributes a result at all.
     */
    public function appliesTo(string $driver): bool;

    public function run(PostdeployContext $context): CheckResult;
}
