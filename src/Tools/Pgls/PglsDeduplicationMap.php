<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools\Pgls;

/**
 * Where this package and the Postgres Language Server check the same thing.
 *
 * ## An allowlist of known overlaps, never a filter
 *
 * Only the pairs written here are treated as the same finding. A PGLS rule absent from this table
 * passes through untouched — which is the direction that matters: a table read as a filter would
 * silently drop whatever nobody thought to list, and the checks most worth having are the ones
 * nobody thought about.
 *
 * ## Why ours wins
 *
 * Not because it is better. Because it carries this package's documentation, its severity, and a
 * remediation written for it — and because a finding that changes id depending on whether an
 * optional binary is installed cannot be baselined. The tool's agreement is not thrown away: it is
 * stamped onto our finding as a confirmation, so a report still says the two agreed.
 *
 * ## Only two pairs, and that is measured
 *
 * The tool's security catalog has six rules. Four of them check ground this package has no rule
 * for at all — extensions in `public`, outdated extension versions, mutable function search paths,
 * unsupported `reg*` types — so they are pure addition and appear here not at all. Listing them
 * with a null counterpart would be a table of what is NOT overlapping, which is every rule that
 * exists and grows without bound.
 */
final readonly class PglsDeduplicationMap
{
    /**
     * PGLS rule name => the SQLens rule that says the same thing.
     *
     * Each pair is a claim that the two rules fire on the SAME CONDITION, not merely on a related
     * one. Where they differ in scope the entry does not belong here: a rule that fires more often
     * than ours would have its extra findings dropped as duplicates of a finding that never
     * existed, which is the one way this table can lose a real problem.
     */
    public const array PAIRS = [
        // Both fire on a table that carries row-level security policies while row-level security
        // itself is switched off — so not one of the policies applies. Same condition, same object,
        // and the more consequential of the two overlaps: it is the shape where somebody wrote the
        // policies, believes they are in force, and they are not.
        'policyExistsRlsDisabled' => 'SEC.RLS.DISABLED',

        // Both fire on a table with row-level security enabled and no policy granting anything —
        // the fail-closed accident, where the table answers empty for every role but its owner.
        'rlsEnabledNoPolicy' => 'SEC.RLS.NO_POLICY',
    ];

    /** The SQLens rule that covers this PGLS rule, or null when nothing here does. */
    public static function sqlensRuleFor(string $pglsRule): ?string
    {
        return self::PAIRS[$pglsRule] ?? null;
    }
}
