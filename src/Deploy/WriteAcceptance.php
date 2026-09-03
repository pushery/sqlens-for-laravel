<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Contracts\ReplicaProbe;

/**
 * Whether an instance will accept writes, and — when it will not — WHICH setting is holding the
 * door shut and what kind of situation that is.
 *
 * ## Why this is not a boolean
 *
 * The package already has a boolean answer to a neighboring question: {@see ReplicaProbe}
 * says "is this a replica", and the shadow captor needs nothing more — it refuses either way.
 *
 * A deploy gate needs more, and the difference is what a reader does next. A standby is a
 * connection pointed at the WRONG HOST; a read-only primary is a SETTING somebody chose. Both
 * refuse `migrate --force`, and a report that merged them would send an operator to edit a config
 * flag on a machine they should not be talking to at all. So the two travel separately, and the
 * variable that decided it travels with them — an operator who is told `super_read_only` does not
 * then go and clear `read_only`, which would change nothing.
 *
 * That is why this is a value object rather than a `bool`: reusing `ReplicaProbe` here would have
 * been one fewer seam and would have thrown away the distinction the check exists to make.
 */
final readonly class WriteAcceptance
{
    private function __construct(
        public bool $readOnly,
        /** The setting or function that decided it — named to the operator exactly as the engine spells it. */
        public string $variable,
        /** What KIND of situation this is, in a phrase that completes "this connection reaches …". */
        public string $kind,
    ) {}

    /** The instance accepts writes. Nothing to name, because nothing is in the way. */
    public static function accepted(): self
    {
        return new self(false, '', '');
    }

    /** The instance refuses writes, because of `$variable`, which puts it in the situation `$kind`. */
    public static function refused(string $variable, string $kind): self
    {
        return new self(true, $variable, $kind);
    }
}
