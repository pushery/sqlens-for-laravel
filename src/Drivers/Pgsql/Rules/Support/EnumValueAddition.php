<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\Support;

use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * The type and the value an `ALTER TYPE … ADD VALUE` names — read once, for the rule that flags it
 * and the template that stages it.
 *
 * The type name alone used to be enough, because the rule only needed to ask whether this migration
 * created the type. The remediation needs the VALUE as well, and a second `preg_match` for it would
 * be the shape this package keeps removing: two patterns agreeing today and disagreeing the first
 * time either is touched.
 *
 * It reads the CANONICAL form, never Laravel's grammar output — and Laravel has no builder for this
 * statement at all, so it always arrives as a raw `DB::statement`, which makes the canonical form
 * the only stable thing about it.
 */
final readonly class EnumValueAddition
{
    private function __construct(
        /** The enum type gaining a value, as the statement names it. */
        public string $type,
        /** The value being added, without its quotes — or null when the statement quotes it oddly. */
        public ?string $value,
    ) {}

    /** The addition this statement performs, or null when it performs none. */
    public static function of(MigrationStatementView $statement): ?self
    {
        if (preg_match('/\bALTER TYPE\s+"?([a-z_][a-z0-9_.]*)"?\s+ADD\s+VALUE\b/i', $statement->canonical, $matches) !== 1) {
            return null;
        }

        // The value is optional in this reading on purpose. `ADD VALUE` accepts `IF NOT EXISTS` and
        // a `BEFORE`/`AFTER` neighbor, and a shape this pattern does not recognize leaves the
        // placeholder standing rather than guessing at a literal — which is the same choice every
        // template here makes about a fact it cannot establish.
        $value = preg_match("/\\bADD\\s+VALUE\\s+(?:IF NOT EXISTS\\s+)?'([^']*)'/i", $statement->canonical, $literal) === 1
            ? $literal[1]
            : null;

        return new self($matches[1], $value);
    }
}
