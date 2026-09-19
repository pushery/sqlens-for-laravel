<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Which unanswerable checks a project has decided it can deploy without.
 *
 * The escape hatch used to be one bit: every reason or none. That was not a judgment about risk,
 * it was the only shape available — the reasons traveled as free-text sentences, so a list could
 * only ever have matched a prefix on prose. Now that every undetermined answer carries an
 * `UndeterminedReason`, the door can be opened for the reason a project has actually accepted and
 * left shut for the ones it has not.
 *
 * The difference is the whole point. "The tool that formats a plan is not installed on this runner"
 * is a fact about the runner that a project may reasonably deploy past. "The privilege table could
 * not be read" is that same project not knowing whether the deploy is allowed to do what it is
 * about to do. A single boolean makes those one decision, and a project that needs the first has
 * to grant the second.
 *
 * Closed is the shipped state, and everything undecidable resolves towards it: a reason this build
 * does not know, a value that is not a list, a list that names nothing valid. A waiver that opens
 * on something it could not read would be the silent green this package exists to refuse, one
 * level up.
 *
 * That direction is a property of the comparison rather than a guard in front of it, which is why
 * there is no arm here for "no reason at all": an answer whose reason is absent simply matches
 * nothing on the list. {@see CheckResult} makes the case unreachable anyway — its constructor is
 * private and the only factory that produces an undetermined answer requires both halves.
 */
final readonly class UndeterminedWaiver
{
    /**
     * @param  list<UndeterminedReason>  $reasons
     */
    private function __construct(
        private bool $everyReason,
        private array $reasons,
    ) {}

    /**
     * Waives nothing — the shipped state.
     */
    public static function closed(): self
    {
        return new self(false, []);
    }

    /**
     * Waives whatever could not answer, which is what `--allow-undetermined` has always meant.
     *
     * Kept as its own state rather than "a list containing every case": the flag is a decision
     * about THIS run made by somebody watching it, and it must not start meaning something
     * narrower the day a case is added to the enum.
     */
    public static function everyReason(): self
    {
        return new self(true, []);
    }

    /**
     * Reads the project's setting, leniently — the config validator is what reports a bad one.
     *
     * Lenient here is not permissive: every unreadable shape narrows the waiver rather than
     * widening it, so a typo in a reason name costs a blocked deploy and never a waved-through one.
     * The validator names the typo; this method must not be the place that decides it was fine.
     */
    public static function fromConfig(mixed $configured): self
    {
        if ($configured === true) {
            return self::everyReason();
        }

        if (! is_array($configured)) {
            return self::closed();
        }

        $reasons = [];

        foreach ($configured as $item) {
            $reason = is_string($item) ? UndeterminedReason::tryFrom($item) : null;

            if ($reason instanceof UndeterminedReason) {
                $reasons[] = $reason;
            }
        }

        return $reasons === [] ? self::closed() : new self(false, $reasons);
    }

    /**
     * The reasons this waiver NAMED on this run, for the line a person reads.
     *
     * Empty when it waives whatever could not answer. `--allow-undetermined` and `true` are not a
     * list of every case and must not be rendered as one: printing the reasons that happened to
     * come up would read as a narrow decision somebody made, when the decision was the wide one.
     *
     * What it returns is what the RUN raised, not what the config holds. A project may name three
     * reasons and meet one; saying all three would claim the run waived more than it did. Sorted,
     * because a deploy log is compared across runs.
     *
     * @param  list<CheckResult>  $undetermined
     * @return list<string>
     */
    public function reasonsItNames(array $undetermined): array
    {
        if ($this->everyReason) {
            return [];
        }

        $named = array_values(array_unique(array_filter(array_map(
            static fn (CheckResult $result): ?string => $result->undeterminedReason?->value,
            $undetermined,
        ))));

        sort($named);

        return $named;
    }

    /**
     * Is this waiver open at all — for every reason, or for a named few?
     *
     * Separate from {@see opensFor()} on purpose, and the difference is what gets reported rather
     * than what gets decided. `opensFor()` answers about THIS run's unanswered checks and is what
     * the exit code turns on; this answers about the waiver itself, which is the fact a deploy log
     * needs even on a run where nothing went unanswered. Collapsing them would make an escape hatch
     * invisible exactly when it changed nothing — and an escape hatch nobody can see used is the
     * state this package refuses one level up.
     */
    public function opensAnything(): bool
    {
        return $this->everyReason || $this->reasons !== [];
    }

    /**
     * Does this waiver cover EVERY answer that could not be given on this run?
     *
     * Every one, not any: the caller has already established that the run is blocked by nothing
     * else, so a single uncovered reason is a question the deploy is about to proceed past
     * unanswered. Partial coverage is the one result that must not read as permission.
     *
     * @param  list<CheckResult>  $undetermined
     */
    public function opensFor(array $undetermined): bool
    {
        if ($undetermined === []) {
            return false;
        }

        if ($this->everyReason) {
            return true;
        }

        return array_all($undetermined, fn (CheckResult $result): bool => in_array($result->undeterminedReason, $this->reasons, true));
    }
}
