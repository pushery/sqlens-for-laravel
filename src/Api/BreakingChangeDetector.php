<?php

declare(strict_types=1);

namespace Pushery\SQLens\Api;

use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\Severity;

/**
 * Compares two API surfaces and says what each difference costs.
 *
 * ## The one design decision worth arguing with
 *
 * A severity RAISE is `allowed_in_minor`, and that is deliberate rather than lax. The security
 * promise says the package gets stricter over time, and it is the whole product: a tool that could
 * never sharpen a rule without a major release would ship its mistakes for a year.
 *
 * The gate that blocked it would be deleted, and after that nothing is protected at all. So the
 * middle class exists to keep the strict class credible — it is not leniency, it is what makes
 * "forbidden without major" a rule somebody will actually live with.
 *
 * ## Removal and rename are the same event, and the message says so
 *
 * A rename looks like two changes — one id gone, one id new — and is reported as the removal,
 * because that is the half that breaks a consumer. Their baseline entry, their ignore list and
 * their suppression all name the old id, and none of them learns the new one. The remedy is the
 * package's own deprecation mechanism, which exists exactly so a rename never has to be a removal.
 *
 * ## The remediation schema is state-dependent, and both states are real
 *
 * While `remediation_schema_stability` is `preview`, a version bump is `allowed_in_minor` — that is
 * what preview MEANS, and pretending otherwise would freeze a schema nobody promised. Once it is
 * promoted, the same bump is forbidden without a major. The classifier reads the stability from the
 * RELEASED surface rather than the current one, because the promise a consumer relies on is the one
 * that shipped, not the one being proposed.
 */
final readonly class BreakingChangeDetector
{
    /**
     * Every difference between a released surface and a candidate one.
     *
     * @param  array<string, mixed>  $released  the surface as it shipped
     * @param  array<string, mixed>  $candidate  the surface the code would produce now
     * @return list<SurfaceChange>
     */
    public static function compare(array $released, array $candidate): array
    {
        return [
            ...self::ruleChanges(self::rulesById($released), self::rulesById($candidate)),
            ...self::contractChanges($released, $candidate),
        ];
    }

    /**
     * The subset that a non-major release must refuse.
     *
     * @param  list<SurfaceChange>  $changes
     * @return list<SurfaceChange>
     */
    public static function blocking(array $changes): array
    {
        return array_values(array_filter(
            $changes,
            static fn (SurfaceChange $change): bool => $change->class->blocksMinorRelease(),
        ));
    }

    /**
     * @param  array<string, array<string, mixed>>  $released
     * @param  array<string, array<string, mixed>>  $candidate
     * @return list<SurfaceChange>
     */
    private static function ruleChanges(array $released, array $candidate): array
    {
        $changes = [];

        foreach ($released as $id => $before) {
            if (! array_key_exists($id, $candidate)) {
                $changes[] = new SurfaceChange(
                    SurfaceChangeClass::ForbiddenWithoutMajor,
                    $id,
                    '',
                    sprintf('the rule `%s` is gone from the surface', $id),
                    'a rename is a removal to every consumer whose baseline, ignore list or '
                    .'suppression names the old id. Deprecate it instead — mark it `deprecated_since` '
                    .'with `replaced_by` pointing at the new id, which keeps the old one resolvable.',
                );

                continue;
            }

            foreach (self::fieldChanges($id, $before, $candidate[$id]) as $change) {
                $changes[] = $change;
            }
        }

        foreach (array_keys($candidate) as $id) {
            if (array_key_exists($id, $released)) {
                continue;
            }

            // A new rule reports findings a consumer's build did not see before, so it is visible
            // rather than free — but it breaks nothing, and requiring a major for it would mean the
            // package could never grow between majors.
            $changes[] = new SurfaceChange(
                SurfaceChangeClass::AllowedInMinor,
                $id,
                '',
                sprintf('the rule `%s` is new', $id),
                'ship it as `preview` if its false-positive behavior is not settled yet.',
            );
        }

        return $changes;
    }

    /**
     * @param  array<string, mixed>  $before
     * @param  array<string, mixed>  $after
     * @return list<SurfaceChange>
     */
    private static function fieldChanges(string $id, array $before, array $after): array
    {
        $changes = [];

        foreach (ApiSurface::RULE_FIELDS as $field) {
            $from = $before[$field] ?? null;
            $to = $after[$field] ?? null;

            if ($from === $to) {
                continue;
            }

            $changes[] = self::fieldChange($id, $field, $from, $to, $after);
        }

        return $changes;
    }

    /** @param  array<string, mixed>  $after  the candidate's own entry, for fields that read a sibling */
    private static function fieldChange(string $id, string $field, mixed $from, mixed $to, array $after): SurfaceChange
    {
        // The prefix is what a consumer greps their CI log for and what their alerting matches on.
        // Changing it is silent on our side and total on theirs.
        if ($field === 'message_prefix') {
            return new SurfaceChange(
                SurfaceChangeClass::ForbiddenWithoutMajor,
                $id,
                $field,
                sprintf('the message prefix of `%s` moved from `%s` to `%s`', $id, self::render($from), self::render($to)),
                'a consumer greps this string. If a new prefix is genuinely needed, it is a new rule '
                .'id beside a deprecated one.',
            );
        }

        // A raise is the product working. A LOWERING is not: a consumer whose gate is set to the old
        // level would stop seeing a finding they had chosen to see, which is a silent loss.
        if ($field === 'severity') {
            return self::severityChange($id, $from, $to);
        }

        if ($field === 'deprecated_since' && $from === null && $to !== null) {
            return new SurfaceChange(
                SurfaceChangeClass::AllowedInMinor,
                $id,
                $field,
                sprintf('`%s` is now deprecated (since %s)', $id, self::render($to)),
                'the rule stays resolvable and announces itself, which is the whole point of '
                .'deprecating rather than removing.',
            );
        }

        // A corrected link costs a reader nothing and a wrong one costs them a dead end.
        if ($field === 'documentation_url') {
            return new SurfaceChange(
                SurfaceChangeClass::AlwaysAllowed,
                $id,
                $field,
                sprintf('the documentation url of `%s` changed', $id),
            );
        }

        if ($field === 'stability') {
            return self::stabilityChange($id, $from, $to, $after);
        }

        // Level, category and the replacement pointer: visible, not breaking.
        return new SurfaceChange(
            SurfaceChangeClass::AllowedInMinor,
            $id,
            $field,
            sprintf('`%s` changed its %s from `%s` to `%s`', $id, $field, self::render($from), self::render($to)),
        );
    }

    /**
     * Both directions of a stability move, and neither of them is cosmetic.
     *
     * The tier decides whether a rule runs at all for somebody who configured nothing:
     * `StabilityGate` admits the default-enabled tier and nothing else, so a move ACROSS that line
     * changes what every unconfigured project sees. Which is why this sits here rather than in the
     * catch-all below, where it lived until a measurement said otherwise.
     *
     * @param  array<string, mixed>  $after  the candidate.s own entry, read for its deprecation
     */
    private static function stabilityChange(string $id, mixed $from, mixed $to, array $after): SurfaceChange
    {
        $wasDefault = self::isDefaultTier($from);
        $isDefault = self::isDefaultTier($to);

        // PROMOTION. The rule was opt-in and now runs for everybody — a new default rule, which is
        // the one change the governance rules reserve for a major. A consumer who chose a level chose the
        // level, never the right of the package to add rules inside it between minors: their build
        // goes red on a migration they did not touch, in a release they read as safe.
        if ($isDefault && ! $wasDefault) {
            return new SurfaceChange(
                SurfaceChangeClass::ForbiddenWithoutMajor,
                $id,
                'stability',
                sprintf('`%s` was promoted from `%s` to `%s`', $id, self::render($from), self::render($to)),
                'promotion turns the rule on for every project that opted into nothing. Ship it '
                .'with a major, where a consumer expects to re-read what fires.',
            );
        }

        // DEMOTION. The opposite loss and the quieter one: a rule a consumer relies on stops
        // running, their gate stays green, and nothing in their build says a check went away.
        // Announced through the deprecation fields it is a retirement, which is exactly what they
        // exist for; without them it is a silent removal wearing a smaller word.
        if ($wasDefault && ! $isDefault) {
            $deprecated = $after['deprecated_since'] ?? null;

            if ($deprecated === null) {
                return new SurfaceChange(
                    SurfaceChangeClass::ForbiddenWithoutMajor,
                    $id,
                    'stability',
                    sprintf('`%s` fell back from `%s` to `%s`', $id, self::render($from), self::render($to)),
                    'a rule that stops running is a removal from the consumer\'s side. Set '
                    .'`deprecated_since` so the retirement announces itself, or keep it stable.',
                );
            }

            return new SurfaceChange(
                SurfaceChangeClass::AllowedInMinor,
                $id,
                'stability',
                sprintf(
                    '`%s` fell back from `%s` to `%s`, announced as deprecated since %s',
                    $id,
                    self::render($from),
                    self::render($to),
                    self::render($deprecated),
                ),
                'the retirement is announced, which is the whole point of deprecating rather than '
                .'dropping a rule.',
            );
        }

        // Both sides on the same side of the line — `preview` to `experimental` and back. Visible,
        // and it changes nothing for a project that configured nothing.
        return new SurfaceChange(
            SurfaceChangeClass::AllowedInMinor,
            $id,
            'stability',
            sprintf('`%s` changed its stability from `%s` to `%s`', $id, self::render($from), self::render($to)),
        );
    }

    /** Whether a recorded tier is the one a run admits without being asked. */
    private static function isDefaultTier(mixed $stability): bool
    {
        if (! is_string($stability)) {
            return false;
        }

        return StabilityTier::tryFrom($stability)?->isEnabledByDefault() === true;
    }

    private static function severityChange(string $id, mixed $from, mixed $to): SurfaceChange
    {
        $before = self::severityRank($from);
        $after = self::severityRank($to);

        if ($after > $before) {
            return new SurfaceChange(
                SurfaceChangeClass::AllowedInMinor,
                $id,
                'severity',
                sprintf('`%s` was raised from `%s` to `%s`', $id, self::render($from), self::render($to)),
                'call it out in the changelog: a consumer whose gate sits between the two will '
                .'start failing on a build that used to pass.',
            );
        }

        // Lowering is the direction nobody notices. A consumer whose severity gate sits above the
        // new value simply stops being told — a finding they chose to see, gone, with a green build.
        return new SurfaceChange(
            SurfaceChangeClass::ForbiddenWithoutMajor,
            $id,
            'severity',
            sprintf('`%s` was lowered from `%s` to `%s`', $id, self::render($from), self::render($to)),
            'a consumer gating above the new value stops seeing this finding, on a build that goes '
            .'green. If the old severity was wrong, say so in a major.',
        );
    }

    /**
     * @param  array<string, mixed>  $released
     * @param  array<string, mixed>  $candidate
     * @return list<SurfaceChange>
     */
    private static function contractChanges(array $released, array $candidate): array
    {
        $changes = [];

        if (($released['exit_codes'] ?? null) !== ($candidate['exit_codes'] ?? null)) {
            $changes[] = new SurfaceChange(
                SurfaceChangeClass::ForbiddenWithoutMajor,
                'exit_codes',
                '',
                'the exit-code table changed',
                'a pipeline branches on these numbers. A new meaning for an existing code is a '
                .'silent behavior change in somebody else\'s deploy script.',
            );
        }

        foreach (['baseline_schema_version', 'report_schema_version'] as $key) {
            if (($released[$key] ?? null) === ($candidate[$key] ?? null)) {
                continue;
            }

            $changes[] = new SurfaceChange(
                SurfaceChangeClass::ForbiddenWithoutMajor,
                $key,
                '',
                sprintf('%s moved from %s to %s', $key, self::render($released[$key] ?? null), self::render($candidate[$key] ?? null)),
                'a consumer holds files in this format. Read the schema-version policy before '
                .'bumping it — the promise is about what an OLD file still means.',
            );
        }

        foreach (self::remediationChange($released, $candidate) as $change) {
            $changes[] = $change;
        }

        foreach (self::extensionContractChanges($released, $candidate) as $change) {
            $changes[] = $change;
        }

        return $changes;
    }

    /**
     * Any move in an extension contract's shape, which is a break for every rule package there is.
     *
     * ## Why it is forbidden in BOTH directions, unlike a rule field
     *
     * A rule may gain a severity and that is a raise, not a break. An interface has no such
     * asymmetry: ADDING a method breaks every existing implementer, removing one breaks every
     * caller, and changing a parameter type or name breaks both — PHP 8 named arguments make a
     * rename observable, and an implementer's override carries the parent's parameter names into
     * its own signature. There is no benign direction, so there is no allowance.
     *
     * ## Reported per METHOD, not per contract
     *
     * "ProvidesRemediation changed" tells an implementer to go and diff nine interfaces. The method
     * and its two signatures are what somebody acts on, and the whole point of this gate is that a
     * consumer learns before their build does.
     *
     * @param  array<string, mixed>  $released
     * @param  array<string, mixed>  $candidate
     * @return list<SurfaceChange>
     */
    private static function extensionContractChanges(array $released, array $candidate): array
    {
        $before = is_array($released['extension_contracts'] ?? null) ? $released['extension_contracts'] : [];
        $after = is_array($candidate['extension_contracts'] ?? null) ? $candidate['extension_contracts'] : [];
        $changes = [];

        // ⚠️ `array_unique`, and the arm below is why it is here. Without it a contract present on
        // both sides is visited twice and every change it carries is reported twice — which reads,
        // in a failing gate, as two separate breaks to go and look at.
        foreach (array_unique([...array_keys($before), ...array_keys($after)]) as $contract) {
            $contract = (string) $contract;
            $was = is_array($before[$contract] ?? null) ? $before[$contract] : [];
            $is = is_array($after[$contract] ?? null) ? $after[$contract] : [];

            foreach (array_unique([...array_keys($was), ...array_keys($is)]) as $method) {
                $method = (string) $method;
                $from = $was[$method] ?? null;
                $to = $is[$method] ?? null;

                if ($from === $to) {
                    continue;
                }

                $changes[] = new SurfaceChange(
                    SurfaceChangeClass::ForbiddenWithoutMajor,
                    'extension_contracts.'.$contract,
                    $method,
                    sprintf('%s::%s went from %s to %s', $contract, $method, self::render($from), self::render($to)),
                    'this is the interface a third-party rule package implements. A signature that '
                    .'moves takes their build with it, and they find out at composer update rather '
                    .'than here.',
                );
            }
        }

        // Deterministic, and sorted on the pair rather than on the message: two runs over one tree
        // must produce identical bytes, and the message embeds a rendered value whose ordering
        // would then depend on its content.
        usort($changes, static fn (SurfaceChange $a, SurfaceChange $b): int => [$a->subject, $a->field] <=> [$b->subject, $b->field]);

        return $changes;
    }

    /**
     * @param  array<string, mixed>  $released
     * @param  array<string, mixed>  $candidate
     * @return list<SurfaceChange>
     */
    private static function remediationChange(array $released, array $candidate): array
    {
        $from = $released['remediation_schema_version'] ?? null;
        $to = $candidate['remediation_schema_version'] ?? null;

        if ($from === $to) {
            return [];
        }

        // Read from the RELEASED surface, not the candidate: the promise a consumer relies on is
        // the one that shipped. Reading the candidate would let a bump and a promotion in the same
        // release grade each other.
        $wasPreview = ($released['remediation_schema_stability'] ?? null) === StabilityTier::Preview->value;

        return [$wasPreview
            ? new SurfaceChange(
                SurfaceChangeClass::AllowedInMinor,
                'remediation_schema_version',
                '',
                sprintf('the remediation schema moved from %s to %s while it is `preview`', self::render($from), self::render($to)),
                'that is what preview means. Promote it deliberately when the shape has settled — '
                .'after that this same bump needs a major.',
            )
            : new SurfaceChange(
                SurfaceChangeClass::ForbiddenWithoutMajor,
                'remediation_schema_version',
                '',
                sprintf('the remediation schema moved from %s to %s after it was promoted out of `preview`', self::render($from), self::render($to)),
                'agents build against this payload. Once it is promised, its shape moves in a major.',
            )];
    }

    /**
     * @param  array<string, mixed>  $surface
     * @return array<string, array<string, mixed>>
     */
    private static function rulesById(array $surface): array
    {
        $byId = [];

        /** @var list<array<string, mixed>> $rules */
        $rules = is_array($surface['rules'] ?? null) ? $surface['rules'] : [];

        foreach ($rules as $rule) {
            $id = $rule['id'] ?? null;

            if (is_string($id) && $id !== '') {
                $byId[$id] = $rule;
            }
        }

        return $byId;
    }

    /** Where a severity sits, with `null` (no severity) at the bottom. */
    private static function severityRank(mixed $severity): int
    {
        if (! is_string($severity)) {
            return 0;
        }

        $order = array_map(static fn (Severity $case): string => $case->value, Severity::cases());
        $position = array_search($severity, $order, true);

        return $position === false ? 0 : $position + 1;
    }

    private static function render(mixed $value): string
    {
        return match (true) {
            $value === null => 'none',
            is_scalar($value) => (string) $value,
            default => 'a structure',
        };
    }
}
