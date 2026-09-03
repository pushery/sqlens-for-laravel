<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Contracts\Rule;

/**
 * The version axis in an AUDIT run, where the server's real version is known — and says so.
 *
 * The lint side already has {@see VersionRuleGate}, which SELECTS the rules that run. Selection is
 * the right shape there, because a fast-path run may have no server at all. An audit is the other
 * situation: it is talking to a live instance, it knows exactly what version answered, and the
 * interesting output is not "which rules ran" but **why the others did not**.
 *
 * That difference is the whole reason this exists rather than a second call to the selector. A gate
 * that returns a shorter list is indistinguishable from a rule set that was always that size, and a
 * level gate which quietly shrinks is one of the ways a tool reports green about work it never did.
 * So every rule comes back with a verdict, and a gated one carries the sentence that explains it.
 *
 * ## Version skew is reported, not resolved
 *
 * When a project pins `assume_server_version` and the live server disagrees, the pin is what the
 * findings were computed against and the real version is what they will be applied to. Both belong
 * in the run header. Escalating that disagreement to a failure is a pre-deploy decision and is
 * deliberately not made here — this layer's job is that nobody can fail to see it.
 */
final readonly class AuditVersionGate
{
    /**
     * @param  ServerVersion|null  $version  the version the audited instance reported, or null when
     *                                       the reading could not determine one. Null is never
     *                                       filled in with a default: a guessed version produces
     *                                       confident findings about a server nobody looked at.
     */
    public function __construct(private ?ServerVersion $version) {}

    /** The verdict for one rule — the single place the three-valued decision is made. */
    public function verdict(Rule $rule): AuditVersionVerdict
    {
        $window = $rule->versionWindow();

        // A rule with no window has nothing to gate on and runs everywhere, known version or not.
        if (! $window->isBounded()) {
            return AuditVersionVerdict::Applicable;
        }

        if (! $this->version instanceof ServerVersion) {
            return AuditVersionVerdict::Undetermined;
        }

        return $window->matches($this->version)
            ? AuditVersionVerdict::Applicable
            : AuditVersionVerdict::Gated;
    }

    /**
     * Why a rule did not run, in a sentence a reader can act on — or null when it did.
     *
     * The version and the window are both named. "Skipped by version" tells somebody that something
     * was skipped; `PG.L6.PK.UUID_V4 needs PostgreSQL 18 or newer, and this server is 17.4` tells
     * them whether to care.
     */
    public function reason(Rule $rule): ?string
    {
        return match ($this->verdict($rule)) {
            AuditVersionVerdict::Applicable => null,
            AuditVersionVerdict::Gated => sprintf(
                '%s is written for %s, and this server reports %s',
                $rule->id(),
                $rule->versionWindow()->describe(),
                $this->version?->toString() ?? '(unknown)',
            ),
            AuditVersionVerdict::Undetermined => sprintf(
                '%s depends on the server version, and this reading could not determine one',
                $rule->id(),
            ),
        };
    }

    /**
     * Every rule that runs — the same answer the selector gives, derived from the verdicts.
     *
     * Derived rather than computed separately: two code paths for "which rules run" would be free
     * to disagree, and the one that disagreed silently would be the one nobody tested.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function applicable(array $rules): array
    {
        return array_values(array_filter(
            $rules,
            fn (Rule $rule): bool => $this->verdict($rule) === AuditVersionVerdict::Applicable,
        ));
    }

    /**
     * The rules that did NOT run, each with its reason — what keeps a shrinking rule set visible.
     *
     * @param  list<Rule>  $rules
     * @return array<string, string> rule id => the sentence explaining it
     */
    public function withheld(array $rules): array
    {
        $withheld = [];

        foreach ($rules as $rule) {
            $reason = $this->reason($rule);

            if ($reason !== null) {
                $withheld[$rule->id()] = $reason;
            }
        }

        return $withheld;
    }
}
