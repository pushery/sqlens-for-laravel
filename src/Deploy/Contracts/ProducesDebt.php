<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Contracts;

use Pushery\SQLens\Findings\Finding;

/**
 * A rule or a check declaring that its finding describes a debt the project keeps owing.
 *
 * ## Why a CHECK can implement it too
 *
 * It began as a rule-only contract because the only debt producer was a static rule reading
 * migrations. That made the oldest debt a project carries the one kind that could never be
 * recorded: a `NOT VALID` constraint already in the database has no migration behind it, so nothing
 * that reads migrations can ever see it, and it was reported identically on every run with no way
 * to date it or to acknowledge it.
 *
 * Nothing in the two methods below was ever about being a rule. What the registrar needs is a thing
 * that names itself, names a kind, and can point at the object one of its findings leaves behind —
 * which is why `id()` is declared HERE rather than assumed from `Rule`. A check already had it; now
 * the registrar can ask for it without knowing which of the two it is holding.
 *
 * ## Why it is an opt-in interface rather than a metadata flag on every rule
 *
 * Most findings are about a statement somebody is ABOUT to run: fix the migration and the finding
 * is gone, and there is nothing to carry forward. A debt is the other kind — an object left in a
 * state the database will keep until somebody acts, whatever happens to the code. Only the rule
 * knows which of the two it produces, and a rule that says nothing produces no ledger entry at all.
 *
 * The negative case is the one worth stating: silence means NO debt. A registrar that guessed from
 * the finding's shape would record entries no rule ever claimed, and a debt account nobody
 * recognizes is one nobody prunes.
 *
 * ## Why the rule names a reference and not a subject
 *
 * The rule says WHICH object; the registrar canonicalizes it. Quoting and casing folding are engine
 * rules, and a rule that canonicalized its own reference would be one more place that has to
 * remember to — and the day one of them forgot, the ledger would grow a duplicate that looks like a
 * second debt. One implementation, one identity, the same rule this package applies to its checks.
 */
interface ProducesDebt
{
    /**
     * The stable identifier this producer's findings carry.
     *
     * Declared on this contract rather than inherited from a rule or a check, so the registrar can
     * join a finding to whatever claimed it without branching on what kind of thing that is. Both
     * implementers already answer it; the contract is what makes the answer reachable.
     */
    public function id(): string;

    /**
     * What KIND of debt this rule's findings describe, e.g. `not_valid_constraint`.
     *
     * Stable and machine-facing: it is part of an entry's derived identity, so changing it renames
     * every debt of that kind and re-opens all of them.
     */
    public function debtKind(): string;

    /**
     * The object this finding leaves behind, as the rule names it — or null when this particular
     * finding carries no lasting state.
     *
     * Nullable because one rule can produce both kinds. A constraint added `NOT VALID` is a debt;
     * the same rule reporting that it could not read the catalog is not, and recording one would
     * put an entry in the ledger for a question rather than for an object.
     */
    public function debtReference(Finding $finding): ?string;
}
