<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules;

use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Drivers\Mysql\Rules\L1\DropColumnRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L1\DropTableRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L1\TruncateRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L2\CopyAlterCharsetRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L2\CopyAlterTypeRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L2\ForeignKeyOnNonStandardKeyRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L2\TableWithoutPrimaryKeyRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L3\AlgorithmLockNotExpressibleRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L3\ExchangePartitionClauseIgnoredRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L3\MissingLockWaitTimeoutRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L3\MixedDdlDmlNotAtomicRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L4\DropWithoutDeployWindowRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L4\EnumChangeRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L4\ExpandWithoutContractRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L4\IdentifierLengthRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L5\FloatForMoneyRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L5\MixedCollationRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L5\NullableForeignKeyInUniqueRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L5\SqlModeMissingErrorForDivisionByZeroRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L5\SqlModeMissingStrictTransTablesRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\CharacterSetServerNotUtf8mb4Rule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\CharsetNotUtf8mb4Rule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\DefaultStorageEngineNotInnodbRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\ExplicitDefaultsForTimestampOffRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\InnodbRowFormatNotDynamicRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\LegacyCollationRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\LowerCaseTableNamesRiskRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\NarrowIntegerPrimaryKeyRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\SqlModeMissingNoEngineSubstitutionRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\SqlModeMissingOnlyFullGroupByRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\TimeZoneNotUtcRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\TimeZoneTablesEmptyRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L7\RedundantIndexRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L7\UnbatchedMassDmlRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L7\UnusedIndexRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L8\ForeignKeyIdSuffixRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L8\SnakeCaseIdentifiersRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L9\MissingCommentRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L9\SelectStarInViewRule;
use Pushery\SQLens\Drivers\Mysql\Rules\L9\TypeImplicitCastRule;
use Pushery\SQLens\Rules\Convention\NamingConvention;
use Pushery\SQLens\Rules\Money\MoneyColumnDictionary;
use Pushery\SQLens\Rules\Pedantic\DocumentationPolicy;

/**
 * The MySQL safety rules, in one deterministic order.
 *
 * Sorted by rule id rather than by declaration order: a report's finding order follows
 * the rules that produced it, and an order that depended on which line a rule was added
 * on would make two runs of an unchanged project differ. Registration goes through the
 * driver, not a global container tag — the driver is what a connection resolves to, and
 * a tag would let an unrelated package inject rules into an engine it knows nothing about.
 *
 * **There is deliberately no level-0 rule here, and that is not an oversight.** The
 * level-0 statement — "the SQL could be captured, and the pretend run raised nothing" —
 * is driver-neutral and already answered by the pre-scan and the three-valued capture,
 * which report `CAP.L0.*` and `CAP.PRESCAN.*` for every engine alike. A MySQL level-0 rule
 * would restate that verdict in a second place, and two places that answer the same
 * question eventually disagree. The registry therefore starts at level 1, and a test holds
 * that gap so a later reader repairs nothing.
 *
 * **A rule is added HERE, once**, so the driver and the fixture suite see each new rule
 * without a second edit. The remaining engine packs (the no-primary-key rule, the
 * deprecated-FK-target rule, the charset and enum rules, the ALGORITHM/LOCK meta-rule)
 * land as their own tickets and join the list below.
 */
final readonly class MysqlRuleSet
{
    /**
     * The lowest level this set contains. Level 0 belongs to the capture layer — see the
     * class docblock; the constant exists so the test asserting the gap has a named source
     * rather than a literal to drift from.
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
     * The shipped MySQL rule set.
     *
     * This is the single source of the production rules: the driver returns it, and the
     * fixture-pair suite judges against it, so what a user runs and what the tests prove are
     * the very same objects. A rule added to the family is added HERE, once.
     *
     * `$projectRoot` is the one construction dependency a safety rule has — it renders a
     * finding's location repo-relative, because an absolute path in a report destroys
     * diffability and leaks the developer's directory layout into a shared artifact.
     *
     * @param  array<string, mixed>  $expect  what the project stated it wants, from `sqlens.audit.expect`
     */
    public static function shipped(string $projectRoot, array $expect = [], ?MoneyColumnDictionary $moneyColumns = null, ?int $unusedIndexMinDays = null, ?NamingConvention $naming = null, ?DocumentationPolicy $documentation = null): self
    {
        $lowerCaseTableNames = $expect['lower_case_table_names'] ?? null;

        return new self([
            new NarrowIntegerPrimaryKeyRule($projectRoot),
            new CharsetNotUtf8mb4Rule($projectRoot),
            new MixedCollationRule($projectRoot),
            new FloatForMoneyRule($projectRoot, $moneyColumns),
            new NullableForeignKeyInUniqueRule($projectRoot),
            new LegacyCollationRule($projectRoot),
            new DropColumnRule($projectRoot),
            new DropTableRule($projectRoot),
            new TruncateRule($projectRoot),
            new DropWithoutDeployWindowRule($projectRoot),
            new ExpandWithoutContractRule($projectRoot),
            new CopyAlterCharsetRule($projectRoot),
            new CopyAlterTypeRule($projectRoot),
            new ForeignKeyOnNonStandardKeyRule($projectRoot),
            new TableWithoutPrimaryKeyRule($projectRoot),
            new AlgorithmLockNotExpressibleRule($projectRoot),
            new ExchangePartitionClauseIgnoredRule($projectRoot),
            new MixedDdlDmlNotAtomicRule($projectRoot),
            new MissingLockWaitTimeoutRule($projectRoot),
            new EnumChangeRule($projectRoot),
            new IdentifierLengthRule($projectRoot),
            new UnbatchedMassDmlRule($projectRoot),
            new RedundantIndexRule($projectRoot),
            new UnusedIndexRule($projectRoot, $unusedIndexMinDays),
            new ExplicitDefaultsForTimestampOffRule($projectRoot),
            new TimeZoneNotUtcRule($projectRoot),
            new TimeZoneTablesEmptyRule($projectRoot),
            // ONE argument carrying the whole expect structure rather than one per key: the next
            // setting SQLens declines to have an opinion about would otherwise widen this signature
            // again, and a factory that grows a parameter per rule stops being a factory.
            new LowerCaseTableNamesRiskRule($projectRoot)
                ->expecting(is_int($lowerCaseTableNames) ? $lowerCaseTableNames : null),
            new InnodbRowFormatNotDynamicRule($projectRoot),
            new CharacterSetServerNotUtf8mb4Rule($projectRoot),
            new DefaultStorageEngineNotInnodbRule($projectRoot),
            new SqlModeMissingStrictTransTablesRule($projectRoot),
            new SqlModeMissingErrorForDivisionByZeroRule($projectRoot),
            new SqlModeMissingNoEngineSubstitutionRule($projectRoot),
            new SqlModeMissingOnlyFullGroupByRule($projectRoot),
            new ForeignKeyIdSuffixRule($projectRoot, $naming ?? NamingConvention::shipped()),
            new SnakeCaseIdentifiersRule($projectRoot, $naming ?? NamingConvention::shipped()),
            new MissingCommentRule($projectRoot, $documentation ?? DocumentationPolicy::shipped()),
            new SelectStarInViewRule($projectRoot),
            new TypeImplicitCastRule($projectRoot),
        ]);
    }

    /**
     * The rules a driver hands to a run, in the deterministic order the constructor established.
     *
     * @return list<Rule>
     */
    public function all(): array
    {
        return $this->rules;
    }
}
