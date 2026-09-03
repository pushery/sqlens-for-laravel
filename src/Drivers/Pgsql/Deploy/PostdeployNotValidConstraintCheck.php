<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Deploy;

use Pushery\SQLens\Contracts\PostdeployCheck;
use Pushery\SQLens\Contracts\PreflightCheck;
use Pushery\SQLens\Deploy\CheckResult;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;
use Pushery\SQLens\Deploy\PendingWork;
use Pushery\SQLens\Deploy\PostdeployContext;
use Pushery\SQLens\Deploy\PreflightContext;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\ConstraintValidationPendingRule;
use Pushery\SQLens\Findings\Finding;

/**
 * The same unvalidated-constraint reading, taken after the deploy instead of before it.
 *
 * ## It adapts rather than reimplements
 *
 * {@see NotValidConstraintCheck} owns the catalog query, the `pg_depend` exclusion, the per-type
 * consequence and the finding identity. This class calls it. A second implementation over the same
 * catalog column would let one command report what the other did not — the same database answering
 * differently depending on which command asked, which this package treats as a defect rather than
 * an inconsistency.
 *
 * ## Why there is no intervention here, unlike the invalid-index adapter
 *
 * That one has a false positive to defuse: `indisvalid = false` is legitimate while a concurrent
 * build is still running, which is the ordinary state seconds after a deploy. `convalidated = false`
 * has no such moment. A constraint is validated or it is not, and nothing in flight makes the
 * reading temporarily wrong.
 *
 * ## The pending set is empty here, and that is the whole point
 *
 * Before a deploy, a constraint with a pending `VALIDATE CONSTRAINT` is not reported — the run being
 * gated is about to settle it. After the deploy there is no pending set at all, so that suppression
 * cannot fire, and it must not: if the deploy really did validate the constraint, the catalog says
 * `convalidated = true` and this check finds nothing. If it still says false, the `VALIDATE` did not
 * take effect — and that is precisely the finding worth having. **What the deploy intended stops
 * mattering the moment it has run; the catalog is the only truth left.**
 *
 * ## What it deliberately does not do
 *
 * It reads no ledger, writes no file, and computes no age. Whether an unvalidated constraint is a
 * tracked debt, how old it is, and whether it moves the exit code are three separate questions with
 * one owner, and it is not this class. Answering them here would put a second fail-semantics beside
 * the one that owns them.
 */
final readonly class PostdeployNotValidConstraintCheck implements PostdeployCheck, ProducesDebt
{
    /**
     * The debt kind, read from the rule that owns the word rather than restated.
     *
     * The reason this class claims a debt at all. Until it did, the only debt
     * producer in the package was the STATIC rule, which reads migrations. A `NOT VALID` constraint
     * that was already in the database when this package arrived has no migration to read, so it
     * was reported on every run, identically, with no `first_seen`, no age and no way to
     * acknowledge it. The oldest debt a project carries was the only one the account did not know.
     *
     * The kind is the SAME word the static rule uses, and taking it from that constant rather than
     * writing it again is the guardrail rather than a nicety: two spellings would be two debts for
     * one constraint, which is precisely the split this ticket exists to close.
     */
    public function debtKind(): string
    {
        return ConstraintValidationPendingRule::DEBT_KIND;
    }

    /**
     * The constraint this finding leaves behind, read from the finding's own object identity.
     *
     * Byte-identical to the static rule's answer by construction, not by agreement: both read
     * `location->objectName`, and both sides were already made to write the same qualified
     * reference there. That is what lets one constraint seen from both directions be one entry.
     */
    public function debtReference(Finding $finding): ?string
    {
        return $finding->location->objectName;
    }

    /**
     * @param  PreflightCheck  $inner  the CONTRACT, not the class: {@see NotValidConstraintCheck} is
     *                                 `final readonly` and cannot be doubled, and the attempt fails
     *                                 as a COMPILE error — an empty log, exit 1, zero reported
     *                                 failures. The default is still the real check, so nothing at
     *                                 a call site changes.
     */
    public function __construct(private PreflightCheck $inner = new NotValidConstraintCheck) {}

    public function id(): string
    {
        return NotValidConstraintCheck::ID;
    }

    public function appliesTo(string $driver): bool
    {
        return $this->inner->appliesTo($driver);
    }

    public function run(PostdeployContext $context): CheckResult
    {
        // Passed through unchanged — findings, pass and `undetermined` alike. The inner check
        // already answers in three values with a named reason, and re-wrapping the verdict here
        // would be a second opinion about a reading this class did not take.
        return $this->inner->run($this->asPreflight($context));
    }

    /**
     * The inner check's world, built from this one.
     *
     * The pending set is EMPTY and correct rather than convenient: after `migrate --force` nothing
     * is pending. The inner check uses it only to stay quiet about a constraint the run is ABOUT to
     * validate, which is a statement about the future — and after the deploy there is no future
     * left to defer to.
     */
    private function asPreflight(PostdeployContext $context): PreflightContext
    {
        return new PreflightContext(
            connection: $context->connection,
            driver: $context->driver,
            serverVersion: $context->serverVersion,
            session: $context->session,
            pending: new PendingWork,
            profile: $context->profile,
            deadlineAt: hrtime(true) + ($context->remainingBudgetMs() * 1_000_000),
            activity: $context->activity,
        );
    }
}
