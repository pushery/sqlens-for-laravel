<?php

declare(strict_types=1);

namespace Pushery\SQLens\Attributes;

use Attribute;

/**
 * The third suppression layer, for the case `.sql` tooling structurally cannot
 * cover: a Laravel migration is PHP, not SQL, so there is no inline SQL comment to
 * hang an exception on (the way PGLS does). The exception hangs on the migration
 * CLASS instead.
 *
 * A `reason` is mandatory, so no silent green. PHP checks it when SQLens instantiates
 * the annotation, not when the migration loads, and one written without a reason, or
 * with one that is empty or only whitespace, suppresses nothing: the finding it names
 * is reported. `until` is only a HINT (a date or version to revisit): it never
 * auto-expires the suppression, because a magic reactivation with no notice is
 * exactly the silent change this package refuses. It is repeatable so one migration
 * can carry several scoped exceptions.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final readonly class SqlensIgnore
{
    /** @var list<string> */
    public array $rules;

    /**
     * @param  array<array-key, string>  $rules  the rule ids this annotation suppresses (re-indexed to a list)
     * @param  string  $reason  why the finding is accepted — mandatory, and one that states nothing
     *                          counts as absent ({@see isReasoned()})
     * @param  string|null  $until  an optional revisit hint (date or version), never an auto-expiry
     */
    public function __construct(array $rules, public string $reason, public ?string $until = null)
    {
        $this->rules = array_values($rules);
    }

    /**
     * Whether this annotation carries a reason, by the rule every attribute here shares. One that
     * does not suppresses nothing.
     */
    public function isReasoned(): bool
    {
        return AttributeReason::states($this->reason);
    }

    /** Whether this annotation suppresses the given rule id. */
    public function suppresses(string $ruleId): bool
    {
        return in_array($ruleId, $this->rules, true);
    }
}
