<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Canonical\Extensions\ExtensionFailure;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\LocationKind;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Turns the findings of a run into the debts a project would owe after it.
 *
 * ## What it decides, and what it deliberately does not
 *
 * It decides which findings describe lasting state, and what the canonical identity of the object
 * is. It does NOT decide whether to write them: it hands back candidates, and the command that
 * asked owns the file. Recording is a write, writes belong to a command a person invoked, and a
 * registrar that wrote on its own would put a run's opinion into version control without anyone
 * asking for it.
 *
 * ## Why the canonicalization lives here rather than in the rules
 *
 * `"Public"."Orders"` and `public.orders` are one object, and the ledger has to agree — otherwise
 * the account grows a duplicate every time the quoting in a migration changes. Canonicalizing in
 * ONE place means there is no rule that can forget to; canonicalizing per rule would mean the
 * guarantee holds until the first one that does.
 *
 * ## Why it knows the clock only as an argument
 *
 * `first_seen` is passed in. The same reasoning as {@see DebtAge}: a registrar that stamped debts
 * from the wall clock would make two runs over an unchanged database produce two different ledgers,
 * and the diff would show a change nobody made.
 */
final readonly class DebtRegistrar
{
    /**
     * The debts a run's findings would record.
     *
     * @param  list<Finding>  $findings
     * @param  list<Rule|ProducesDebt>  $rules  what ran, so a finding can be traced back to the
     *                                          thing that claims it — a finding carries an id, not
     *                                          an object. Rules and deploy CHECKS both appear here:
     *                                          the catalog side is where a legacy debt is visible
     *                                          at all, and it is not made of rules
     * @param  string  $firstSeen  the UTC calendar date this run records, `YYYY-MM-DD`
     * @return list<DebtEntry>
     */
    public static function candidates(
        array $findings,
        array $rules,
        DriverCanonicalization|ExtensionFailure $canonicalization,
        string $firstSeen,
    ): array {
        // A driver whose canonicalization the registry could not produce proposes nothing. The
        // union is taken HERE rather than narrowed by the caller, and that placement was measured:
        // no run can reach this method with a failure in hand, because the same registry decides
        // whether the driver is known at all — a driver without a canonicalization is refused at
        // resolution, with a message about the ENGINE and long before any finding exists. A guard
        // in the caller was therefore an unreachable branch sitting in the middle of the run.
        //
        // Silence is the right answer only because of that. An identity built from a raw string
        // would be the duplicate this class exists to prevent — `public.orders_ck` and `orders_ck`
        // as two debts about one constraint — so proposing candidates anyway is the one thing that
        // must not happen, and the state that would need announcing cannot occur.
        if ($canonicalization instanceof ExtensionFailure) {
            return [];
        }

        $claiming = [];

        foreach ($rules as $rule) {
            if ($rule instanceof ProducesDebt) {
                $claiming[$rule->id()] = $rule;
            }
        }

        $candidates = [];

        foreach ($findings as $finding) {
            $entry = self::candidate($finding, $claiming[$finding->ruleId] ?? null, $canonicalization, $firstSeen);

            if ($entry instanceof DebtEntry) {
                $candidates[] = $entry;
            }
        }

        return $candidates;
    }

    /**
     * What a run could have OBSERVED, from the same claimant set its candidates come from.
     *
     * Derived here rather than written at the call site, and that placement is the point: a scope
     * assembled by hand would be a second statement of which kinds a run produces, and the day the
     * two disagreed the reconciliation would either prune a population nobody read or refuse to
     * prune one it did. Asking the claimants makes the two answers one answer.
     *
     * The ORIGINS are the caller's to state, because they are a property of the command rather than
     * of the rules: `sqlens:lint` reads migrations, `sqlens:audit` reads the catalog, and the same
     * rule could in principle be reached by either.
     *
     * @param  list<Rule|ProducesDebt>  $rules
     */
    public static function scopeOf(array $rules, DebtOrigin ...$origins): DebtScope
    {
        $kinds = [];

        foreach ($rules as $rule) {
            if ($rule instanceof ProducesDebt) {
                $kinds[] = $rule->debtKind();
            }
        }

        return DebtScope::of(array_values(array_unique($kinds)), array_values($origins));
    }

    /**
     * One finding's debt, or null at any of the four points where it is not one.
     *
     * Written as a sequence of named refusals rather than one condition: each of them is a
     * different reason a finding does not become an entry, and a reader chasing a debt that failed
     * to appear needs to know which.
     */
    private static function candidate(
        Finding $finding,
        ?ProducesDebt $rule,
        DriverCanonicalization $canonicalization,
        string $firstSeen,
    ): ?DebtEntry {
        // No rule claimed it. Silence means no debt — a registrar that guessed from a finding's
        // shape would record entries nobody recognizes, and an account nobody recognizes is one
        // nobody prunes.
        if (! $rule instanceof ProducesDebt) {
            return null;
        }

        $reference = $rule->debtReference($finding);

        // The rule looked and said this particular finding leaves nothing behind — the same rule
        // reporting that it could not read the catalog, for instance.
        if ($reference === null || $reference === '') {
            return null;
        }

        $subject = DebtSubject::of($reference, self::typeOf($finding), $canonicalization);

        // The reference could not be canonicalized. Recording the raw string is what creates the
        // duplicate the canonicalization exists to prevent, so nothing is recorded at all.
        if (! $subject instanceof DebtSubject) {
            return null;
        }

        return DebtEntry::of(
            kind: $rule->debtKind(),
            ruleId: $finding->ruleId,
            driver: $finding->context->driver,
            object: $subject->canonical,
            migration: self::migrationOf($finding),
            firstSeen: $firstSeen,
        );
    }

    /** What the finding says the object is, defaulting to a table when it names no type. */
    private static function typeOf(Finding $finding): SchemaObjectType
    {
        return $finding->location->objectType ?? SchemaObjectType::Table;
    }

    /**
     * The migration reference a reader can open, or the empty string for a debt found in the
     * catalog rather than in a file.
     *
     * A catalog finding has no migration behind it that this run can see — the statement that
     * created the wreckage ran in some earlier deploy. Naming a file that did not cause it would be
     * worse than naming none: somebody would open it looking for a statement that is not there.
     */
    private static function migrationOf(Finding $finding): string
    {
        return $finding->location->kind === LocationKind::Migration
            ? (string) $finding->location->file
            : '';
    }
}
