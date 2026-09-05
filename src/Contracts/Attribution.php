<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

/**
 * Whether a catalog id names something the READER wrote, or something the run OBSERVED.
 *
 * ## The one question a bad/good pair depends on
 *
 * An example pair shows the form that trips a rule and the form that does not. That only teaches
 * something when the finding is caused by text the reader can rewrite. `GEN.L1.DML_WITHOUT_WHERE`
 * has such a form; `CAP.L0.SERVER_UNREACHABLE` does not, and inventing one for it would be
 * confident, concrete, and about something else.
 *
 * ## Why it is a field and not a rule of thumb about `source`
 *
 * `source` almost decides it and not quite: the `deploy` family splits down the middle. Two of its
 * entries name a state a migration LEFT — a constraint added `NOT VALID` and never validated, a
 * MySQL check written `NOT ENFORCED` — and both have a clean pair. The other twenty-two name what
 * the run found in the world: a lock another session holds, a replica behind, an index whose build
 * died. Measured before this enum existed: no shipped field separated the two. `severity` is null
 * for `PREFLIGHT.STATISTICS_UNREAD` and for `PREFLIGHT.LOCK_BLOCKER` alike, and `confidence`,
 * `downtime_class` and `documentation_state` do not divide them either.
 *
 * So the answer had to be declared. It is declared HERE rather than in a list inside a test, because
 * a list in a test certifies itself: the next id is classified by whoever remembers to add a line.
 *
 * ## It is a claim in BOTH directions
 *
 * `Authored` says an example pair is owed. `Observed` says one would be wrong, and a guard refuses
 * it — otherwise the classification is decoration. That second half is what makes the first mean
 * anything: without it, "no example" and "not classified yet" look identical forever.
 */
enum Attribution: string
{
    /**
     * The finding names something in the reader's own migration, schema or source.
     *
     * A bad/good pair is owed, and `RuleDocumentationCompletenessTest` requires it.
     */
    case Authored = 'authored';

    /**
     * The finding names what the run found in the world, or what it could not do.
     *
     * An unreachable server, a lock another session holds, an index whose build died, a rule set
     * that matched nothing. There is no migration that causes it and none that avoids it, so an
     * example pair is refused rather than merely absent.
     */
    case Observed = 'observed';
}
