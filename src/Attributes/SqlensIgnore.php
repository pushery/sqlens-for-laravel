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
 * A `reason` is mandatory — there is no way to construct one without it, so no
 * silent green. `until` is only a HINT (a date or version to revisit): it never
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
     * @param  string  $reason  why the finding is accepted — mandatory
     * @param  string|null  $until  an optional revisit hint (date or version), never an auto-expiry
     */
    public function __construct(array $rules, public string $reason, public ?string $until = null)
    {
        $this->rules = array_values($rules);
    }

    /** Whether this annotation suppresses the given rule id. */
    public function suppresses(string $ruleId): bool
    {
        return in_array($ruleId, $this->rules, true);
    }
}
