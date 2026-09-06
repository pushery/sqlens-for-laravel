<?php

declare(strict_types=1);

namespace Pushery\SQLens\Attributes;

use Attribute;

/**
 * "This raw SQL is deliberate, and here is why."
 *
 * ## This is a JUSTIFICATION, not a suppression — and the difference is visible in the report
 *
 * The package already has {@see SqlensIgnore}, and reaching for it here would be the obvious move
 * and the wrong one. The two say different things:
 *
 * - `#[SqlensIgnore]` means *"I know, do not tell me."* The finding is produced and then hidden, and
 *   it appears in the report as `suppressed_by` — visible, counted, attributable.
 * - `#[RawSql]` means *"the rule's own question is answered."* No finding is produced at all,
 *   because the thing the rule asks for — a written reason — is present.
 *
 * Run both through one channel and a report can no longer distinguish "somebody looked at this and
 * accepted it" from "this was never a finding". That distinction is the whole reason this package
 * carries a `suppressed_by` field, so collapsing it here would quietly remove the answer to a
 * question every audit asks.
 *
 * The ownership follows the same line: suppression is one component's concern, justification is the
 * analyse suite's, and neither reimplements the other.
 *
 * ## `interpolation:` is a SECOND question, and it is separate on purpose
 *
 * `reason:` answers *"why raw SQL"*. It does NOT answer *"why is this runtime value in the
 * statement's text instead of in its parameters"*, and letting it do so would be the expensive
 * mistake available here: a method reasoned *"we need a window function"* would then silently
 * accept an interpolated request value, and the injection rule would be off wherever this
 * annotation is on.
 *
 * So the second answer is written separately, or it is not given:
 *
 * ```php
 * #[RawSql(
 *     reason: 'partitioned-table DDL; the query builder cannot express PARTITION BY',
 *     interpolation: 'the suffix is a formatted date computed here — PostgreSQL binds no identifier',
 * )]
 * ```
 *
 * The two are also independent in the other direction: a `reason:` the run's policy refuses does
 * not withdraw an `interpolation:` that is written, because they are answers to different
 * questions and one being unsatisfactory says nothing about the other.
 *
 * **Why a justification and not a suppression here.** The alternative a project has today is a
 * PHPStan `ignoreErrors` entry, and it is worse in both directions that matter: it carries no
 * reason, so nobody later knows whether the line was considered; and it is scoped by PATH, so the
 * next interpolation in that file — one that DOES have a binding available — is silenced with it.
 * An annotation is at the call site, carries the sentence, and covers what it sits on.
 *
 * ## The reason is mandatory, at the language level
 *
 * Not checked by a rule, not validated at runtime — a constructor argument. An annotation without a
 * reason is a PHP error before any analysis starts, which is the only enforcement that cannot be
 * forgotten. An empty string still fails the rule, because a reason nobody wrote is the state this
 * whole mechanism exists to surface.
 *
 * ## Targets a METHOD as well as a class
 *
 * Deliberately finer than {@see SqlensIgnore}, which is class-only. A class with one carefully
 * reasoned raw statement and one careless one is an ordinary shape, and a class-level annotation
 * would excuse both — the careless one silently, which is the direction that costs something.
 *
 * ```php
 * #[RawSql(reason: 'partitioned-table DDL; the query builder cannot express PARTITION BY')]
 * public function createPartition(string $suffix): void
 * {
 *     DB::statement("CREATE TABLE orders_{$suffix} PARTITION OF orders FOR VALUES …");
 * }
 * ```
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::TARGET_FUNCTION)]
final readonly class RawSql
{
    /**
     * @param  string  $reason  why raw SQL is the right tool here — for the next reader, never parsed
     * @param  string|null  $until  an optional revisit hint (a date or a version), never an auto-expiry
     * @param  string|null  $interpolation  why a runtime value is in the statement TEXT rather than
     *                                      in its parameters — a SECOND question, see below
     */
    public function __construct(
        public string $reason,
        public ?string $until = null,
        public ?string $interpolation = null,
    ) {}

    /**
     * Whether this annotation answers the INTERPOLATION question as well.
     *
     * Same emptiness rule as {@see isReasoned()}, for the same reason: `interpolation: ''` satisfies
     * PHP and states nothing.
     */
    public function justifiesInterpolation(): bool
    {
        return $this->interpolation !== null && trim($this->interpolation) !== '';
    }

    /**
     * Whether this annotation actually carries a reason.
     *
     * The constructor makes the argument required; it cannot make it meaningful. `reason: ''`
     * satisfies PHP and answers nothing, so the rule that reads this treats it as absent — an empty
     * reason is how a justification requirement turns into a formality that everybody types and
     * nobody means.
     */
    public function isReasoned(): bool
    {
        return trim($this->reason) !== '';
    }
}
