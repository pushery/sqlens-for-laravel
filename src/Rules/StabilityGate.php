<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Categories\CategoryFilter;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Levels\LevelGate;

/**
 * The maturity axis: which stability tiers a run admits.
 *
 * ## The promise this exists to keep
 *
 * The versioning contract says a new rule lands as `preview` and runs only on request. That is not
 * a nicety — without it, **every minor release is a silent breaking change for any pipeline that
 * branches on the exit code.** A rule added in 0.4.1 would start failing builds that passed on
 * 0.4.0, over code nobody touched, and the only signal would be a red pipeline on a Tuesday.
 *
 * So the tier has to gate something. Before this class existed, {@see StabilityTier} was a field
 * that traveled all the way into the report and changed nothing on the way — the report showed
 * `preview` beside a finding that had already failed the build. A metadata field with no call site
 * is a promise in the changelog and nothing in the code.
 *
 * ## Why it is a separate filter rather than a condition inside another one
 *
 * It sits beside {@see LevelGate} and
 * {@see CategoryFilter}, matching their shape on purpose. The three axes
 * are orthogonal and answer different questions — level asks how strict, category asks about what,
 * stability asks how settled — and folding any of them into another is how a run ends up with a
 * scope nobody can predict from the flags.
 *
 * ## The default is the strict one
 *
 * An empty selection means **stable only**, not "everything". That is the opposite of
 * {@see CategoryFilter}, where empty means all, and the difference is
 * deliberate: an unconfigured category axis means the operator expressed no preference, while an
 * unconfigured stability axis is the whole point of the contract. Reading "no opinion" as "run the
 * unfinished rules too" would hand every project the behavior the tier exists to protect them from.
 */
final readonly class StabilityGate
{
    /** @param  list<StabilityTier>  $enabled  the tiers to admit beyond the stable one */
    public function __construct(private array $enabled = []) {}

    /**
     * A gate from configured tier names, ignoring anything it does not recognize.
     *
     * Unknown values are dropped here rather than refused, because refusing them is the config
     * validator's job and it does it before a run starts — a second, quieter rejection at this
     * seam would mean two places deciding what a valid tier is.
     *
     * @param  list<string>  $names
     */
    public static function fromNames(array $names): self
    {
        $tiers = [];

        foreach ($names as $name) {
            $tier = StabilityTier::tryFrom($name);

            if ($tier instanceof StabilityTier) {
                $tiers[] = $tier;
            }
        }

        return new self($tiers);
    }

    /**
     * A gate from whatever the configuration holds, however malformed.
     *
     * Both runners read the same key and had started narrowing it identically — two copies of one
     * decision, which is one copy too many for a decision this consequential. The narrowing lives
     * here so there is a single answer to "what does a malformed stability value mean".
     *
     * And that answer is **no opt-in**, never a full one. The failure direction of this axis is
     * admitting unfinished rules into somebody's pipeline; a config the package could not read must
     * not be the door that happens through.
     */
    public static function fromConfig(mixed $value): self
    {
        return self::fromNames(
            is_array($value) ? array_values(array_filter($value, is_string(...))) : [],
        );
    }

    /**
     * Every tier this run admits, in declaration order — what was ALLOWED to run.
     *
     * Not what reported. That distinction is the whole value of putting it in the run header: a
     * preview rule that FINDS something marks itself at the finding, so it is already visible. The
     * one that finds nothing is invisible, and two runs over one unchanged tree — one admitting
     * preview, one not — then produce identical headers over different coverage.
     *
     * Derived from `StabilityTier::cases()` rather than assembled from `$enabled`, so a tier added
     * to the enum is named here without anyone remembering to. Assembling it by hand is how a list
     * that looks complete stops being complete.
     *
     * @return list<StabilityTier>
     */
    public function admitted(): array
    {
        return array_values(array_filter(
            StabilityTier::cases(),
            $this->admits(...),
        ));
    }

    /**
     * The same set as configuration names, for the run header and the report envelope.
     *
     * @return list<string>
     */
    public function admittedNames(): array
    {
        return array_map(static fn (StabilityTier $tier): string => $tier->value, $this->admitted());
    }

    /** Whether this tier runs in this configuration. */
    public function admits(StabilityTier $tier): bool
    {
        if ($tier->isEnabledByDefault()) {
            return true;
        }

        return in_array($tier, $this->enabled, true);
    }

    /**
     * The rules this run admits.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function apply(array $rules): array
    {
        return array_values(array_filter(
            $rules,
            fn (Rule $rule): bool => $this->admits($rule->stability()),
        ));
    }

    /**
     * The rules this run held back, so a report can say so instead of leaving a silence.
     *
     * The counterpart matters as much as the filter. A run that quietly dropped four rules and one
     * that had four fewer rules to begin with produce identical output, and only one of them is a
     * configuration the operator might want to change.
     *
     * @param  list<Rule>  $rules
     * @return list<Rule>
     */
    public function withheld(array $rules): array
    {
        return array_values(array_filter(
            $rules,
            fn (Rule $rule): bool => ! $this->admits($rule->stability()),
        ));
    }
}
