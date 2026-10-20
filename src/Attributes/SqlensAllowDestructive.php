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
 * It does not silence the rule. The finding is still produced; the opt-in is applied at
 * the reporting layer's destructive-opt-in suppression source as a named, visible
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
 * A `reason` is mandatory, so an opt-in is never silent: the code records why the data
 * may go, the same discipline `#[SqlensIgnore]` enforces. PHP checks it when SQLens
 * instantiates the attribute, not when the migration loads, and an opt-in written without
 * a reason, or with one that is empty or only whitespace, consents to nothing: the
 * destruction stays flagged. Applying to the migration CLASS (like `#[SqlensIgnore]`)
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

    /**
     * Whether this opt-in carries a reason, by the rule every attribute here shares. One that does
     * not consents to nothing.
     */
    public function isReasoned(): bool
    {
        return AttributeReason::states($this->reason);
    }
}
