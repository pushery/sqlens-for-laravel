<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L1\DropColumnRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L1\DropSchemaRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L1\DropTableRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L1\TruncateRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\ConstraintNotValidatedRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\CreateIndexNotConcurrentRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\DropIndexNotConcurrentRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\SetNotNullScanRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L2\TypeChangeRewriteRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\ConcurrentlyInTransactionRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\MissingLockTimeoutRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\MissingStatementTimeoutRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\RiskyOpsSingleTransactionRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support\ExpectedTimeouts;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\CheckEnumChangeRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\ConstraintValidationPendingRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\DropWithoutDeployWindowRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\EnumAddValueRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\EnumValueRemovedRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\ExpandWithoutContractRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\IdentifierLengthRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L4\TypeNarrowingRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\CollationVersionMismatchRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\FloatForMoneyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\ForeignKeyWithoutIndexRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\MoneyTypeRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\NullableForeignKeyInUniqueRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L5\TableWithoutPrimaryKeyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\DefaultTransactionIsolationDriftRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\DefaultTransactionReadOnlyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\JsonNotJsonbRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\NarrowIntegerPrimaryKeyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\SerialNotIdentityRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\StandardConformingStringsOffRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\TimestampWithoutTimeZoneRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\TimeZoneNotUtcRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\UuidV4PrimaryKeyRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L7\DataChecksumsDisabledRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L7\RedundantIndexRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L7\UnbatchedMassDmlRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L7\UnusedIndexRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L8\ForeignKeyIdSuffixRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L8\SnakeCaseIdentifiersRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L9\MissingCommentRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L9\SelectStarInViewRule;
use Pushery\SQLens\Drivers\Pgsql\Rules\L9\TypeImplicitCastRule;
use Pushery\SQLens\Rules\Convention\NamingConvention;
use Pushery\SQLens\Rules\Money\MoneyColumnDictionary;
use Pushery\SQLens\Rules\Pedantic\DocumentationPolicy;

/**
 * The PostgreSQL safety rules, in one deterministic order.
 *
 * Sorted by rule id rather than by declaration order: a report's finding order follows
 * the rules that produced it, and an order that depended on which line a rule was added
 * on would make two runs of an unchanged project differ. Registration goes through the
 * driver, not a global container tag — the driver is what a connection resolves to, and
 * a tag would let an unrelated package inject rules into an engine it knows nothing
 * about.
 *
 * **There is deliberately no level-0 rule here, and that is not an oversight.** The
 * level-0 statement — "the SQL could be captured, and the pretend run raised nothing" —
 * is driver-neutral and already answered by the pre-scan and the three-valued capture,
 * which report `CAP.L0.*` and `CAP.PRESCAN.*` for every engine alike. A PostgreSQL
 * level-0 rule would restate that verdict in a second place, and two places that answer
 * the same question eventually disagree. The registry therefore starts at level 1, and
 * a test holds that gap so a later reader repairs nothing.
 */
final readonly class PgsqlRuleSet
{
    /**
     * The lowest level this set contains. Level 0 belongs to the capture layer — see
     * the class docblock; the constant exists so the test asserting the gap has a named
     * source rather than a literal to drift from.
     */
    public const int LOWEST_LEVEL = 1;

    /** @var list<Rule> */
    public array $rules;

    /** @param  list<Rule>  $rules */
    public function __construct(array $rules = [])
    {
        usort($rules, static fn (Rule $a, Rule $b): int => $a->id() <=> $b->id());

        $this->rules = $rules;
    }

    /**
     * The shipped PostgreSQL rule set, built for one project root.
     *
     * This is the single source of the production rules: the driver returns it, and
     * the fixture-pair suite judges against it, so what a user runs and what the tests
     * prove are the very same objects. A rule added to the family is added HERE, once,
     * and both the driver and the tests see it without a second edit.
     *
     * The projectRoot reaches each rule so a finding's location is repo-relative — the
     * one construction dependency a safety rule has. The expected-timeouts set and the
     * single-transaction lock threshold reach their rules the same way: both default to
     * the shipped values, so the driver passes the project's configured ones and the
     * fixture suite gets the strict defaults without wiring config.
     */
    public static function forProjectRoot(string $projectRoot, ?ExpectedTimeouts $expectedTimeouts = null, int $maxLocksPerTransaction = 1, ?string $uuidGeneratedBy = null, ?MoneyColumnDictionary $moneyColumns = null, ?int $unusedIndexMinDays = null, ?NamingConvention $naming = null, ?DocumentationPolicy $documentation = null): self
    {
        $expectedTimeouts ??= ExpectedTimeouts::all();

        return new self([
            new DropColumnRule($projectRoot),
            new DropSchemaRule($projectRoot),
            new DropTableRule($projectRoot),
            new TruncateRule($projectRoot),
            new ConstraintNotValidatedRule($projectRoot),
            new CreateIndexNotConcurrentRule($projectRoot),
            new DropIndexNotConcurrentRule($projectRoot),
            new SetNotNullScanRule($projectRoot),
            new TypeChangeRewriteRule($projectRoot),
            new ConcurrentlyInTransactionRule($projectRoot),
            new MissingLockTimeoutRule($projectRoot, $expectedTimeouts->requires(ExpectedTimeouts::LOCK_TIMEOUT)),
            new MissingStatementTimeoutRule($projectRoot, $expectedTimeouts->requires(ExpectedTimeouts::STATEMENT_TIMEOUT)),
            new RiskyOpsSingleTransactionRule($projectRoot, $maxLocksPerTransaction),
            new CheckEnumChangeRule($projectRoot),
            new ConstraintValidationPendingRule($projectRoot),
            new ExpandWithoutContractRule($projectRoot),
            new DropWithoutDeployWindowRule($projectRoot),
            new EnumAddValueRule($projectRoot),
            new IdentifierLengthRule($projectRoot),
            new EnumValueRemovedRule($projectRoot),
            new TypeNarrowingRule($projectRoot),
            new ForeignKeyWithoutIndexRule($projectRoot),
            new FloatForMoneyRule($projectRoot, $moneyColumns),
            new MoneyTypeRule($projectRoot),
            new NullableForeignKeyInUniqueRule($projectRoot),
            new CollationVersionMismatchRule($projectRoot),
            new JsonNotJsonbRule($projectRoot),
            new NarrowIntegerPrimaryKeyRule($projectRoot),
            new SerialNotIdentityRule($projectRoot),
            new TimestampWithoutTimeZoneRule($projectRoot),
            new UuidV4PrimaryKeyRule($projectRoot, $uuidGeneratedBy),
            new TimeZoneNotUtcRule($projectRoot),
            new StandardConformingStringsOffRule($projectRoot),
            new DefaultTransactionIsolationDriftRule($projectRoot),
            new DefaultTransactionReadOnlyRule($projectRoot),
            new DataChecksumsDisabledRule($projectRoot),
            new RedundantIndexRule($projectRoot),
            new UnbatchedMassDmlRule($projectRoot),
            new UnusedIndexRule($projectRoot, $unusedIndexMinDays),
            new TableWithoutPrimaryKeyRule($projectRoot),
            new ForeignKeyIdSuffixRule($projectRoot, $naming ?? NamingConvention::shipped()),
            new SnakeCaseIdentifiersRule($projectRoot, $naming ?? NamingConvention::shipped()),
            new MissingCommentRule($projectRoot, $documentation ?? DocumentationPolicy::shipped()),
            new SelectStarInViewRule($projectRoot),
            new TypeImplicitCastRule($projectRoot),
        ]);
    }

    /**
     * The rules a driver hands to a run. Empty until the rule packs land — and an empty
     * set is an honest "no rules yet", never read as "checked, all clean": the run
     * reports its active-rule count, and a category filter that admits nothing raises a
     * named undetermined.
     *
     * @return list<Rule>
     */
    public function all(): array
    {
        return $this->rules;
    }
}
