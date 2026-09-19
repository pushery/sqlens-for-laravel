<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Reporting\CredentialRedaction;

/**
 * What one preflight check answered, in exactly three shapes.
 *
 * ## Why `undetermined` cannot be built without a reason
 *
 * A gate that cannot look is not a gate that found nothing, and the whole value of this package
 * rests on those two never collapsing into one another. A private constructor with three factories
 * is what makes the difference structural rather than a convention somebody remembers: there is no
 * way to spell an undetermined result that does not say why.
 *
 * ## Why there is no fourth state
 *
 * `skipped` and `n/a` are the values a reader reaches for next, and both are refused. The report is
 * a public contract from 1.0 on, so a fourth value is an undeclared one in a JSON document other
 * people's pipelines parse — and worse, it would blur the one distinction that matters: "did not
 * apply here" is a fact about the DRIVER, "could not answer" is a fact about the RUN. A check that
 * does not apply is never executed and so never produces a result at all.
 */
final readonly class CheckResult
{
    private function __construct(
        public string $checkId,
        public Outcome $outcome,
        /** Why an undetermined answer is undetermined — present exactly when it is. */
        public ?string $reason,
        /** @var list<Finding> what the check found; empty for a clean pass */
        public array $findings,
        /**
         * The same reason as a NAME — present exactly when {@see $reason} is.
         *
         * Both, and not one instead of the other. The sentence above is specific on purpose: WHICH
         * view refused, WHICH privilege is missing, WHICH budget ran out, and a category alone
         * would make two very different situations look alike at exactly the moment somebody needs
         * to tell them apart. That argument stands and is why this is an addition rather than a
         * replacement.
         *
         * What the sentence cannot do is be named in a configuration. `suppression.allow_undetermined`
         * takes a list of reasons and validates it against this enum; the deploy waiver was a
         * boolean, because a list on that side would have had to match a prefix on prose — precise
         * looking, and wrong the first time somebody rewords a sentence.
         */
        public ?UndeterminedReason $undeterminedReason = null,
    ) {}

    /**
     * The check ran and the database is fine on this question.
     *
     * Findings are still allowed: a pass can carry advisory findings that do not block, which is how
     * a gate reports something worth knowing without stopping a deploy over it.
     *
     * @param  list<Finding>  $findings
     */
    public static function pass(string $checkId, array $findings = []): self
    {
        return new self($checkId, Outcome::Pass, null, $findings);
    }

    /**
     * The check ran and found something the deploy should stop for.
     *
     * At least one finding is required, and that is not bookkeeping: a failure with nothing to show
     * gives whoever is blocked no way to act, and "the gate said no" without a reason is how a gate
     * gets configured away.
     *
     * @param  non-empty-list<Finding>  $findings
     */
    public static function fail(string $checkId, array $findings): self
    {
        return new self($checkId, Outcome::Fail, null, $findings);
    }

    /**
     * The check could not answer, and here is why — in words somebody can act on.
     *
     * The reason travels as BOTH a name and a sentence, and the sentence is why it is not only a
     * name: it is specific — WHICH view refused, WHICH privilege is missing, WHICH budget ran out —
     * and a category alone would make two very different situations look alike at exactly the
     * moment somebody needs to tell them apart.
     *
     * The name is what a configuration can hold, and it is composed into the sentence rather than
     * kept beside it so that the token is legible exactly where the failure is read. An operator who
     * wants to allow this answer has to name it in `allow_undetermined`, and prose alone would send
     * them to look the token up.
     *
     * The shape `name: detail` is not new: 24 of the 43 call sites had written it out by hand,
     * independently, before there was anything to compose it from. The remaining 19 GAIN a prefix
     * they did not print before, which is a deliberate change to their rendered text and the reason
     * five pinned message tests moved with this commit.
     *
     * @param  list<Finding>  $findings
     */
    public static function undetermined(string $checkId, UndeterminedReason $reason, string $detail, array $findings = []): self
    {
        $trimmed = trim($detail);

        if ($trimmed === '') {
            throw new InvalidCheckResult(
                "the check {$checkId} answered undetermined with no reason. An undetermined result "
                .'without one is indistinguishable from a pass to everybody downstream, which is the '
                .'single failure this package exists to prevent.'
            );
        }

        return new self($checkId, Outcome::Undetermined, $reason->value.': '.$trimmed, $findings, $reason);
    }

    /**
     * The same answer with its reason redacted — the one place every check's words pass through.
     *
     * Applied here rather than in eleven checks, and that is the point rather than convenience: a
     * database error MESSAGE carries the connection block Laravel appends to it (host, user,
     * database, the SQL), so every site that quotes one inherits a leak, and the twelfth check would
     * arrive without whatever treatment the first eleven got. Measured over a recorded MCP session
     * against a connection whose every field was a marked string: all of them came back.
     *
     * The reason gets SMALLER, never emptier. A redacted sentence still says which check could not
     * answer and what it was doing — an undetermined without a reason is the one thing this class
     * refuses to construct.
     */
    public function redactedWith(CredentialRedaction $redaction): self
    {
        if ($this->reason === null) {
            return $this;
        }

        return new self($this->checkId, $this->outcome, $redaction->in($this->reason), $this->findings, $this->undeterminedReason);
    }

    /** Whether this answer should stop a deploy under a fail-closed gate. */
    public function isBlocking(): bool
    {
        return $this->outcome !== Outcome::Pass;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $projection = [
            'check_id' => $this->checkId,
            'outcome' => $this->outcome->value,
            'reason' => $this->reason,
            // ADDITIVE, and the one field that makes a waiver expressible. A consumer writing its
            // own rule from this document had to match a prefix on the sentence above; now it can
            // name the reason. Absent on a pass, like every other null field here.
            'undetermined_reason' => $this->undeterminedReason?->value,
            'findings' => array_map(static fn (Finding $f): array => $f->toArray(), $this->findings),
        ];

        // One rule for the whole document: a field with no value is ABSENT, never present-as-null.
        return array_filter($projection, static fn (mixed $value): bool => $value !== null);
    }
}
