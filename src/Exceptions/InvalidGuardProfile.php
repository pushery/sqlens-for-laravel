<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use InvalidArgumentException;

/**
 * A guard profile that cannot be resolved — refused at boot rather than absorbed.
 *
 * Every one of these could have been a quiet fallback to "guard off", and that is precisely the
 * failure this class exists to make impossible. Off and misconfigured have the same effect and
 * opposite meanings: one is a decision somebody made, the other is a typo that turned every
 * guardrail in the application into a no-op while the config still reads as though they are on.
 *
 * The message always names the thing that was not found AND what was available, because the fix is
 * almost always visible in that comparison.
 */
final class InvalidGuardProfile extends InvalidArgumentException
{
    /** @param list<string> $available */
    public static function unknownProfile(string $name, array $available): self
    {
        return new self(sprintf(
            'sqlens.guard.profile names `%s`, and sqlens.guard.profiles defines %s. This is an '
            .'error rather than "guard off": a name nothing defines would silently disable every '
            .'runtime guardrail while the configuration still reads as though they are on. Set '
            .'`profile` to null to turn guard off on purpose.',
            $name,
            $available === [] ? 'no profiles at all' : 'only: '.implode(', ', $available),
        ));
    }

    public static function notAName(mixed $value): self
    {
        return new self(sprintf(
            'sqlens.guard.profile must be a non-empty profile name or null, and it is %s. Null is '
            .'the way to say "off"; anything else is read as a name and has to match one.',
            get_debug_type($value),
        ));
    }

    /** @param list<string> $available */
    public static function unknownChannel(string $profile, string $channel, array $available): self
    {
        return new self(sprintf(
            'The guard profile `%s` logs to channel `%s`, which config/logging.php does not define. '
            .'Available: %s. Refused at BOOT rather than at the first violation — a logger that '
            .'throws when a guardrail finally has something to say fails at the worst possible '
            .'moment, with the application already misbehaving.',
            $profile,
            $channel,
            implode(', ', $available),
        ));
    }

    /** @param list<string> $available */
    public static function unknownConnection(string $profile, string $connection, array $available): self
    {
        return new self(sprintf(
            'The guard profile `%s` names connection `%s`, which database.connections does not '
            .'define. Available: %s. A whitelist that matches nothing looks exactly like one that '
            .'matches everything, so the guardrail would be silently off for the connection you '
            .'meant to protect.',
            $profile,
            $connection,
            implode(', ', $available),
        ));
    }

    public static function notPositive(string $profile, string $key, mixed $value): self
    {
        return new self(sprintf(
            'The guard profile `%s` sets `%s` to %s, and it must be a positive integer. Zero is '
            .'refused rather than read as "no bound": a threshold of zero reports every query ever '
            .'run and a truncation length of zero logs the empty string — both are an unset value '
            .'spelled wrongly, and both leave a guardrail that looks like it works.',
            $profile,
            $key,
            // `get_debug_type` and never `var_export`: a config value is user input, and the
            // architecture preset forbids `var_export` for exactly this reason — the one place it
            // would be convenient is the one place a value must not be echoed back.
            is_int($value) ? (string) $value : get_debug_type($value),
        ));
    }
}
