<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Privacy;

/**
 * Whether a run is looking at production — three-valued, like every other verdict here.
 *
 * ## Why a boolean is not enough for this question
 *
 * The existing name detector answers `false` for a connection called `pgsql` against a database
 * called `shop`, and that `false` means two different things: "this is not production" and "nothing
 * about this says either way". For the guard that detector was built for, collapsing them is
 * correct — it is the LAST line before a destructive mode, and an unmarked name is simply not the
 * evidence it needs.
 *
 * For a rule it is wrong, and wrong in the direction this package refuses everywhere: a rule that
 * read "cannot tell" as "not production" would report a `pass` on a server it never placed, and a
 * pass is a statement that the check ran and found the situation acceptable.
 */
enum ProductionVerdict
{
    /** The application declares production, or the names say so. */
    case Production;

    /** The application declares an environment that is plainly not production. */
    case NotProduction;

    /**
     * Nothing available said either way.
     *
     * Not a failure and not a pass — a question. A rule that depends on the environment reports
     * this as `undetermined` with the reason named, which is the only honest answer when the fact
     * a verdict rests on was never established.
     */
    case Undetermined;
}
