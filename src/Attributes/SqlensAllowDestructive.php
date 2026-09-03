<?php

declare(strict_types=1);

namespace Pushery\SQLens\Attributes;

use Attribute;

/**
 * The opt-in for the destructive migration rules — the level-1 family (DROP TABLE, DROP
 * COLUMN, TRUNCATE, and a mass UPDATE/DELETE with no WHERE, all in `up()`) and the
 * level-4 deploy-window rule. A migration that carries this attribute has said, in the
 * code and with a mandatory reason, that the destruction is intended.
 *
 * It does NOT silence the rule. The finding is still produced; the opt-in is applied at
 * the reporting layer's destructive-opt-in suppression source as a NAMED, VISIBLE
 * suppression — the reason shown, the operation still listed — so a run always shows the
 * migration destroys data. That is the point: "the loss was reviewed" and "the check
 * never looked" are different facts, and the report must not confuse them.
 *
 * It is deliberately COARSER than `#[SqlensIgnore]`: that suppresses a named finding
 * after the fact, one rule id at a time; this declares up front that destruction in
 * this migration is on purpose, and clears the whole destructive family at once. A
 * migration that drops three tables should not have to name three rule ids to say the
 * obvious thing once.
 *
 * A `reason` is mandatory — the constructor cannot be called without one — so an
 * opt-in is never silent: the code records WHY the data may go, the same discipline
 * `#[SqlensIgnore]` enforces. Applying to the migration CLASS (like `#[SqlensIgnore]`)
 * because a Laravel migration is PHP with no inline SQL comment to hang it on.
 */
#[Attribute(Attribute::TARGET_CLASS)]
final readonly class SqlensAllowDestructive
{
    /**
     * @param  string  $reason  why the destruction is intended — mandatory, so no
     *                          destructive operation is ever waved through silently
     */
    public function __construct(public string $reason) {}
}
