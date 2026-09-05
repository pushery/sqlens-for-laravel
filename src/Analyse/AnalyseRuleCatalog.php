<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Severity\Severity;

/**
 * Every rule the analyse suite can report, with the metadata a consumer reads.
 *
 * ## What went wrong without it
 *
 * `SEC.INJ.RAW_SQL_WITHOUT_REASON` shipped as a working PHPStan rule that appeared in NO catalog.
 * Measured: the id occurred exactly once in the whole tree, as the constant inside the rule itself.
 * So `sqlens:rules` did not list it, the MCP `explain-rule` tool could not explain it, no agent
 * artifact carried it, and a reader who saw the id in their PHPStan output and went looking for it
 * in SQLens' own catalog found nothing — an id shaped like every other rule id in the package and
 * behaving like none of them.
 *
 * It also carried an id the package's own format contract REJECTED. `SEC.INJ.` was not one of the
 * security areas, and nothing said so, because the property test that refuses a malformed id runs
 * over the registry — and the registry had never heard of this rule. Two gaps producing one silence:
 * an id nobody validated because of a rule nobody listed.
 *
 * That is why this class exists and why it is the SINGLE place the metadata lives. The rule reads
 * its own id from here rather than declaring it twice.
 */
final readonly class AnalyseRuleCatalog
{
    /** The prefix analyse findings report under — the suite, not a driver. */
    public const string MESSAGE_PREFIX = 'sqlens.analyse';

    /**
     * The suite's rules, sorted by id.
     *
     * Sorted here rather than at the call site so every consumer sees one order — the export sorts
     * again, but a second consumer that did not would otherwise depend on declaration order.
     *
     * @return list<AnalyseRuleMetadata>
     */
    public static function metadata(): array
    {
        $rules = [self::unjustifiedRawSql(), self::staleRawSqlReason(), self::rawInterpolation(), self::dynamicIdentifier()];

        usort($rules, static fn (AnalyseRuleMetadata $a, AnalyseRuleMetadata $b): int => $a->id <=> $b->id);

        return $rules;
    }

    /**
     * A runtime value assembled into a statement's text.
     *
     * **Severity `High`, and the contrast with its neighbor is the point.** The policy rule reports
     * a missing sentence; this one reports that a value reached the STATEMENT rather than the
     * parameters — the property that decides whether an injection is possible at all. It is still
     * not a claim that the value is attacker-controlled: that would be taint analysis, which this
     * package does not do, and the limitation says so where a consumer can read it.
     *
     * **Level `Capturable`** for the same reason as its neighbor: a security rule is weighed on the
     * severity axis, and parking it higher would let a strictness setting quietly decide a security
     * question.
     */
    private static function rawInterpolation(): AnalyseRuleMetadata
    {
        return new AnalyseRuleMetadata(
            id: RawInterpolationRule::RULE_ID,
            category: Category::Security,
            level: Level::Capturable,
            severity: Severity::High,
            stability: StabilityTier::Stable,
            messagePrefix: self::MESSAGE_PREFIX,
            suites: [Suite::Analyse],
            limitations: [
                'a syntactic pattern rather than taint analysis: it reports that a runtime value '
                .'reached the statement TEXT, and makes no claim about whether that value is '
                .'attacker-controlled or reachable from a request',
                'never quotes the query: a finding travels into CI logs, SARIF files and agent '
                .'artifacts, and a reproduced fragment would be a second copy of whatever the '
                .'statement touched',
                'sees exactly one call site — a value assembled unsafely in another method is '
                .'reported as undetermined by the classifier and is deliberately NOT reported here, '
                .'because doubt raised as a high-severity finding teaches a team to ignore the rule',
                'a placeholder count that disagrees with the bindings array degrades to undetermined '
                .'rather than reporting: the text is still constant, so nothing can be injected '
                .'through it',
            ],
            reportedIdentifier: RawInterpolationRule::IDENTIFIER,
        );
    }

    /**
     * A column or sort direction taken from the request.
     *
     * **Severity `High`, like its interpolation sibling and for a sharper reason.** An identifier is
     * part of the statement's grammar and has no binding form at all, so there is no safe way to
     * pass user input through — only an allowlist. Where the interpolation rule reports a value that
     * SHOULD have been bound, this reports one that CANNOT be.
     */
    private static function dynamicIdentifier(): AnalyseRuleMetadata
    {
        return new AnalyseRuleMetadata(
            id: DynamicIdentifierRule::RULE_ID,
            category: Category::Security,
            level: Level::Capturable,
            severity: Severity::High,
            stability: StabilityTier::Stable,
            messagePrefix: self::MESSAGE_PREFIX,
            suites: [Suite::Analyse],
            limitations: [
                'a syntactic pattern rather than taint analysis: it reports that the request is '
                .'VISIBLE in the expression, and makes no claim about whether the value is reachable '
                .'from an attacker or what it contains',
                'sees one expression in one scope — an allowlist applied in another method is '
                .'invisible, and the result is reported as undetermined with a named reason rather '
                .'than as a pass',
                'validated input still counts: validation checks a value SHAPE, and an identifier\'s '
                .'danger is not its shape',
                'the *Raw methods are deliberately not collected here — orderByRaw() is a raw-SQL '
                .'fragment and belongs to the interpolation rule, so one call never produces two '
                .'findings under two ids',
            ],
            reportedIdentifier: DynamicIdentifierRule::IDENTIFIER,
        );
    }

    /**
     * Raw SQL with no written reason.
     *
     * **Severity `Low`, deliberately, and it is the field most likely to be argued about.** The rule
     * does not claim the statement is unsafe — it never reads the query text. It says nobody wrote
     * down why raw SQL was chosen, which is a policy gap rather than a vulnerability. Rating a
     * policy gap `High` would put it beside findings that describe an actual exposure, and the first
     * team to meet both in one report would learn to discount the axis rather than the rule.
     *
     * **Level `Capturable`, so it is never gated behind a strictness appetite.** A security-category
     * rule is weighed on the severity axis; parking it at a higher level would mean a project on a
     * low level silently stops being asked, which is the level axis quietly deciding a security
     * question.
     *
     * **Suite `Analyse` alone.** It is not in the security suite's list yet because the security
     * command does not collect analyse findings yet. Naming the suite here anyway would put a rule
     * in a report that never receives it — a promise the tree cannot keep today.
     */
    private static function unjustifiedRawSql(): AnalyseRuleMetadata
    {
        return new AnalyseRuleMetadata(
            id: UnjustifiedRawSqlRule::RULE_ID,
            category: Category::Security,
            level: Level::Capturable,
            severity: Severity::Low,
            stability: StabilityTier::Stable,
            messagePrefix: self::MESSAGE_PREFIX,
            suites: [Suite::Analyse],
            limitations: [
                'never reads the query text: this rule reports a MISSING REASON, never an unsafe '
                .'statement, and SQLens performs no taint analysis at any point',
                'syntactic detection only: a call reached through a variable, a callable string or a '
                .'container binding is invisible to it, and it reports what it saw rather than '
                .'claiming the rest is clean',
                'a class-level #[RawSql] covers every call in that class, so one reasoned raw '
                .'statement and one careless one are excused together — the method-level form exists '
                .'to avoid exactly that',
                'a suppression whose rule ids are not literal strings does not suppress, because '
                .'resolving them would mean evaluating project code during analysis; the finding '
                .'stays visible, which is the safe direction',
            ],
            reportedIdentifier: UnjustifiedRawSqlRule::IDENTIFIER,
        );
    }

    /**
     * A written reason that no longer covers any raw SQL.
     *
     * **Severity `Info`, and it is a step below its own sibling on purpose.** The policy rule says a
     * decision was never written down; this one says a decision was written down and has since
     * stopped applying. Nothing is exposed either way, and this one is the milder of the two — the
     * project did the thing that was asked, and the code moved afterwards. Rating it any higher
     * would mean a tidy-up item arriving at the same weight as a missing one.
     *
     * **It is still worth a finding, and that is the argument the ticket behind it makes better than
     * this docblock could.** An exemption that outlives its reason reads for years as a decision
     * somebody weighed, and the next reader trusts it. A consuming project had built the two-way
     * check by hand and could not retire it in favor of this package, because trading a two-way
     * check for a one-way one is not adoption.
     *
     * **Level `Capturable`** for the same reason as every rule in this suite.
     *
     * **`stable` rather than `preview`, and the question was put rather than skipped.** The
     * package's own breaking-change detector raises it on any new rule: *ship it as `preview` if
     * its false-positive behavior is not settled yet.* This one HAS a false-positive class and it
     * is written down in the example register — a call reached through a variable or a container
     * binding is invisible to the collectors, so an annotation covering only such a call reads as
     * stale, and the rule then asks somebody to delete something true.
     *
     * It ships stable anyway, for three reasons that hold together. That false-positive class is
     * the SAME syntactic limit {@see UnjustifiedRawSqlRule} has, and that rule is stable. The
     * severity is `info`, so a false positive costs a line in a report rather than a red build.
     * And the consuming project this was built for runs a hand-written check with the identical
     * limit as a hard gate today — shipping the replacement behind an opt-in would ask them to
     * consent to something strictly better than what they already trust.
     */
    private static function staleRawSqlReason(): AnalyseRuleMetadata
    {
        return new AnalyseRuleMetadata(
            id: StaleRawSqlReasonRule::RULE_ID,
            category: Category::Security,
            level: Level::Capturable,
            severity: Severity::Info,
            stability: StabilityTier::Stable,
            messagePrefix: self::MESSAGE_PREFIX,
            suites: [Suite::Analyse],
            limitations: [
                'never reads the query text and performs no taint analysis: it reports that an '
                .'annotation covers no raw SQL any more, which is a bookkeeping fact about the '
                .'attribute rather than any claim about the code under it',
                'counts a justification as live if ANY raw-SQL call site this suite collects is '
                .'attributed to it — including a fragment or a dynamic identifier, which the policy '
                .'rule itself does not report, because a reason covering one of those is doing its job',
                'syntactic detection only, the same limit its sibling has: a call reached through a '
                .'variable or a container binding is invisible, so an annotation covering only such a '
                .'call reads as stale',
                'a class-level annotation is kept alive by a raw statement in ANY of its methods, so '
                .'the coarse form is also the one least likely to be reported as stale',
                'says nothing under policy off or inside an excluded path: a project that switched '
                .'the duty off must not get findings about the annotations it wrote while it was on',
            ],
            reportedIdentifier: StaleRawSqlReasonRule::IDENTIFIER,
        );
    }
}
