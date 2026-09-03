<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Severity\Severity;

/**
 * At what age an outstanding debt starts to be worth more attention.
 *
 * ## Why this is not {@see EscalationThresholds}
 *
 * That one escalates on the SIZE of the object a finding names — rows and bytes, per operation.
 * This one escalates on the AGE of a debt. The two share an asymmetry and nothing else: both may
 * only ever RAISE a severity. A big table does not make an unsafe migration safe, and a young debt
 * is not a paid one. Merging them would put two unrelated inputs behind one name, and the first
 * person to change a number would not know which axis they moved.
 *
 * ## What a threshold may and may not do
 *
 * It raises a severity. It never creates a finding, never removes one, and never changes a rule id.
 * The debt reported on day 1 and the debt reported on day 400 are the SAME finding about the same
 * object — the older one is simply louder. A threshold that minted its own rule id would give one
 * problem two names in a project's history and break every baseline entry on the day it crossed.
 *
 * ## Why the exit code is somewhere else
 *
 * Escalating a severity and failing a build are different decisions, and this class only makes the
 * first. `deploy.debt.fail_at` decides whether an age breaks the run, and it lives with the command
 * that owns the exit code. Otherwise a project could not have "tell me loudly, but do not stop the
 * deploy at 3am" — which is the setting most projects actually want.
 */
final readonly class DebtThresholds
{
    /** The ticket's numbers, in UTC calendar days: mention at a month, warn at a quarter, escalate at half a year. */
    public const array DEFAULTS = [
        DebtTier::Notice->value => 30,
        DebtTier::Warning->value => 90,
        DebtTier::Error->value => 180,
    ];

    /** @param array<string, int> $days tier value => the age at which that band starts */
    private function __construct(private array $days) {}

    /**
     * The configured thresholds, falling back per-band to the shipped default.
     *
     * A partial override is honored per band rather than rejected: a project that only wants to
     * move `error` should not have to restate the other two, and restating them is how they drift
     * from the shipped numbers without anybody deciding to.
     *
     * ## Why it takes `mixed`
     *
     * The argument is whatever the project's config holds, and narrowing it is this type's own job
     * rather than each caller's. Two commands read this setting; a private narrowing helper beside
     * each of them was two copies of one decision, free to answer differently about one file. The
     * shape is refused by the config validator long before it gets here — this is the second line,
     * and its whole purpose is that a malformed housekeeping setting cannot take a run down.
     *
     * @param  mixed  $configured  from `sqlens.deploy.debt.thresholds`, unnarrowed
     */
    public static function fromConfig(mixed $configured = []): self
    {
        $days = [];
        $keyed = is_array($configured) ? $configured : [];

        foreach (self::DEFAULTS as $tier => $default) {
            $value = $keyed[$tier] ?? null;

            $days[$tier] = is_int($value) && $value >= 0 ? $value : $default;
        }

        return new self($days);
    }

    /** The age at which a band starts, in UTC calendar days. */
    public function daysFor(DebtTier $tier): int
    {
        return $this->days[$tier->value] ?? self::DEFAULTS[$tier->value];
    }

    /**
     * The loudest band this age has reached, or null while it has reached none.
     *
     * Read loudest-first so a configuration whose numbers are not ascending still answers with the
     * strongest band that applies rather than the first one in declaration order. Such a
     * configuration is a config error and is reported as one — but a value object asked a question
     * answers it, instead of quietly picking the weaker reading of a file somebody already got
     * wrong.
     */
    public function tierFor(int $ageInDays): ?DebtTier
    {
        foreach (DebtTier::loudestFirst() as $tier) {
            if ($ageInDays >= $this->daysFor($tier)) {
                return $tier;
            }
        }

        return null;
    }

    /**
     * The severity a debt of this age carries, given what the finding already said.
     *
     * Never lowers. A rule that considered a debt High on its own merits keeps High at any age —
     * age is a reason to care MORE, and a threshold that could quiet a finding would make the
     * report depend on how long somebody had been ignoring it.
     */
    public function escalate(Severity $base, int $ageInDays): Severity
    {
        $tier = $this->tierFor($ageInDays);

        if (! $tier instanceof DebtTier) {
            return $base;
        }

        return $tier->severity()->value === $base->value || ! $this->outranks($tier->severity(), $base)
            ? $base
            : $tier->severity();
    }

    /** Whether the first severity is louder than the second, on the shipped order of the enum. */
    private function outranks(Severity $candidate, Severity $base): bool
    {
        $order = array_map(static fn (Severity $s): string => $s->value, Severity::cases());

        return array_search($candidate->value, $order, true) > array_search($base->value, $order, true);
    }
}
