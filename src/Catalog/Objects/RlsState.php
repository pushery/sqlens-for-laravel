<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

/**
 * The row-level security state of one table: whether it is on, whether it binds the owner too, and
 * the policies that decide what a row is allowed to be.
 *
 * ## Three states, and the middle one is the accident
 *
 * - **RLS off** — every row is visible to anyone with `SELECT`. Correct for most tables, and a finding
 *   only for the ones a project says hold tenant data.
 * - **RLS on with no policy** — the FAIL-CLOSED accident: PostgreSQL denies every row, to everybody
 *   except the owner. The table looks fine in the catalog and returns nothing at runtime.
 * - **RLS on with policies** — the intended state, and the one where a policy that admits everything
 *   makes the protection ceremonial.
 *
 * ## Why `forced` is its own field and not a detail
 *
 * `ENABLE ROW LEVEL SECURITY` does not apply to the table's OWNER. An application connecting as the
 * role that owns its tables — which is the ordinary Laravel setup — bypasses every policy on the
 * database without any attribute showing up anywhere. `FORCE ROW LEVEL SECURITY` is what closes that,
 * and its absence is invisible in every policy listing.
 */
final readonly class RlsState
{
    /**
     * @param  list<RlsPolicy>  $policies  sorted by name
     */
    private function __construct(
        public string $table,
        public bool $enabled,
        public bool $forced,
        public array $policies,
        public Readability $readability,
        /**
         * The role that owns the table, or an empty string when the reading could not establish one.
         *
         * Carried because `ENABLE` does not apply to the owner and `FORCE` is what closes that: an
         * application connecting as the role that owns its tables — the ordinary Laravel setup —
         * bypasses every policy on the database, and the only way to tell is to compare this name
         * against the role the audit connected as.
         */
        public string $owner,
    ) {}

    /**
     * @param  list<RlsPolicy>  $policies
     */
    public static function of(string $table, bool $enabled, bool $forced, array $policies, Readability $readability, string $owner = ''): self
    {
        usort($policies, static fn (RlsPolicy $a, RlsPolicy $b): int => $a->name <=> $b->name);

        return new self(trim($table), $enabled, $forced, $policies, $readability, trim($owner));
    }

    /** RLS is on and NOTHING may pass — the fail-closed accident, which reads as a working setup. */
    public function isLockedOut(): bool
    {
        return $this->enabled && $this->policies === [];
    }

    /**
     * Whether any policy admits every row it is asked about.
     *
     * Permissive policies are OR-ed, so ONE that admits everything makes the rest ceremonial — which
     * is why this asks "any" rather than "all". A restrictive policy can only narrow, so it cannot
     * produce this state and is not counted.
     */
    public function hasAlwaysTruePolicy(): bool
    {
        // Derived from the NAMES rather than from a second walk of the same list. Two derivations of
        // one fact drift, and only one of them would be the one a test covers.
        return $this->alwaysTruePolicyNames() !== [];
    }

    /**
     * The permissive policies that admit every row, by name — sorted, because the policies are.
     *
     * Names rather than a count, because the remediation is per policy: somebody has to open the one
     * that is wrong, and a finding saying "two policies admit everything" sends them through the
     * whole list. A catalog rule speaks once per object and names every offending member; this is
     * that list.
     *
     * @return list<string>
     */
    public function alwaysTruePolicyNames(): array
    {
        return array_values(array_map(
            static fn (RlsPolicy $policy): string => $policy->name,
            array_filter($this->policies, static fn (RlsPolicy $policy): bool => $policy->permissive && $policy->admitsEverything()),
        ));
    }

    /**
     * The permissive policies whose WRITE check admits everything while their read filter does not.
     *
     * Deliberately excludes the ones already named by {@see self::alwaysTruePolicyNames()}: a policy
     * that admits every row on both paths is one problem, and reporting it twice would bury the
     * write-path finding under a repetition of the read-path one.
     *
     * @return list<string>
     */
    public function alwaysTrueCheckPolicyNames(): array
    {
        return array_values(array_map(
            static fn (RlsPolicy $policy): string => $policy->name,
            array_filter(
                $this->policies,
                static fn (RlsPolicy $policy): bool => $policy->permissive
                    && $policy->checkAdmitsEverything()
                    && ! $policy->admitsEverything(),
            ),
        ));
    }

    /**
     * @return array{table: string, enabled: bool, forced: bool, owner: string, policies: list<array<string, mixed>>, readability: array<string, mixed>}
     */
    public function toArray(): array
    {
        return [
            'table' => $this->table,
            'enabled' => $this->enabled,
            'forced' => $this->forced,
            'owner' => $this->owner,
            'policies' => array_map(static fn (RlsPolicy $policy): array => $policy->toArray(), $this->policies),
            'readability' => $this->readability->toArray(),
        ];
    }
}
