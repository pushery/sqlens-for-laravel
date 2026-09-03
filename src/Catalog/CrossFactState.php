<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * Whether a fact measured ALONGSIDE a server setting is a real answer, a real absence, or a gap.
 *
 * ## The distinction this enum exists to force
 *
 * A server-baseline rule is far more useful when it can say "and here are the fourteen columns this
 * already affects" than when it can only say "this setting is dangerous". But the moment a rule
 * reports a count, it inherits a question the setting itself never had: **is zero an answer, or is
 * it what a failed query looks like?**
 *
 * Those are opposite situations with identical output. A catalog that reports no affected column
 * because it could not be read looks exactly like one with nothing to report — and the rule then
 * says "nothing else is affected" about a database it never examined. That is the package's silent
 * green, one layer below where it usually appears.
 *
 * Five separate rules needed this and each invented its own discriminator: a nullable string, a
 * `hasAttribute()` check, an explicit zero, a `'yes'|'no'|null` triple. Five conventions is five
 * chances for one of them to collapse the two cases, so the state travels as its own value and is
 * mandatory rather than inferable.
 */
enum CrossFactState: string
{
    /** The query ran and found something. The value is real. */
    case Measured = 'measured';

    /** The query ran and found nothing. Zero is the ANSWER — a rule may say "none" out loud. */
    case None = 'none';

    /**
     * The query could not run — no privilege, no such relation, a budget exhausted.
     *
     * A rule that reaches this reports `undetermined` with the carried reason. It never falls
     * through to silence, and it never treats it as {@see self::None}: the whole point of separating
     * them is that one of the two justifies a sentence about the database and the other does not.
     */
    case Unavailable = 'unavailable';
}
