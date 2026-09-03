<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Pushery\SQLens\Exceptions\InvalidAnalyseConfiguration;

/**
 * How hard this run presses on the justification duty.
 *
 * ## Why three modes and not a boolean
 *
 * The duty has two independent halves, and a project can want one without the other. `documented`
 * asks *"is there a reason?"*; `strict` additionally asks *"does the reason say anything?"*. A team
 * adopting the rule on an existing codebase wants the first for a release or two — every call site
 * annotated, some of them thinly — and the second afterwards. Collapsing them into one switch makes
 * that migration impossible and gets the rule turned off instead.
 *
 * ## What NO mode touches
 *
 * The injection rules. `SEC.INJ.RAW_INTERPOLATION` and `SEC.INJ.DYNAMIC_IDENTIFIER` report an
 * exposure rather than a missing sentence, and severity is not level-gated in this package.
 * A configuration line that could silence them would let one line of neon disable half the security
 * surface — which is why this enum is read by the policy rule and by the justification collector,
 * and by nothing else. `PolicyGateSparesSecurityTest` holds that boundary against a real run.
 */
enum AnalysePolicy: string
{
    /** The duty does not apply. The injection rules are unaffected. */
    case Off = 'off';

    /** A reason must exist and say more than whitespace. The default. */
    case Documented = 'documented';

    /** …and it must not be one of the configured placeholders. */
    case Strict = 'strict';

    /**
     * The mode a project asked for, or a named refusal.
     *
     * `tryFrom` plus an explicit throw rather than `from`: PHP's own `ValueError` names the enum
     * class and the bad value, which tells a developer nothing about what they may write instead.
     *
     * ## Why this takes a bool as well, and why that is not laxity
     *
     * **NEON reads the bare word `off` as the boolean `false`.** Measured against the shipped
     * parser:
     *
     *     policy: off
     *     → Deprecated: Neon: keyword 'off' is deprecated, use true/yes or false/no.
     *     → Invalid configuration: 'parameters › sqlens › analyse › policy' expects to be string,
     *       false given.
     *
     * So the single most likely thing a developer types — the mode's own name, unquoted — never
     * arrives here as a string, and the error they meet talks about types rather than about the
     * setting. `no` behaves the same way.
     *
     * Accepting `false` therefore does not widen the vocabulary; it repairs a spelling the format
     * takes away. `true` is refused, because `on`/`yes` names no mode this package has and guessing
     * which one it meant is exactly the silent fallback the rest of this class exists to prevent.
     */
    public static function fromConfig(string|bool $value): self
    {
        if ($value === false) {
            return self::Off;
        }

        if ($value === true) {
            throw InvalidAnalyseConfiguration::booleanPolicy(self::accepted());
        }

        return self::tryFrom($value) ?? throw InvalidAnalyseConfiguration::unknownPolicy($value, self::accepted());
    }

    /** @return list<string> */
    public static function accepted(): array
    {
        return array_map(static fn (self $case): string => $case->value, self::cases());
    }

    /** Does this mode ask for a reason at all? */
    public function asksForAReason(): bool
    {
        return $this !== self::Off;
    }

    /** Does this mode also weigh WHAT the reason says? */
    public function weighsTheReason(): bool
    {
        return $this === self::Strict;
    }
}
