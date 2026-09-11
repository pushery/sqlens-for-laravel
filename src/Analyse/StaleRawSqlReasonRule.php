<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use Pushery\SQLens\Rules\RuleDocumentationUrl;

/**
 * A `#[RawSql]` that no longer justifies anything.
 *
 * ## Why an exemption needs an expiry, and why this is the more valuable half
 *
 * {@see UnjustifiedRawSqlRule} asks for a reason when the raw SQL is WRITTEN. Nothing asked again
 * afterwards. Rewrite the call into a query-builder chain, delete the statement, move it to another
 * class — the annotation stays, sitting on code that runs no raw SQL, and reads for the rest of the
 * project's life as an exemption somebody weighed. Nobody deletes it, because nothing says it is
 * dead.
 *
 * A consuming project had built exactly this by hand: a gate step pinning an explicit list of raw-SQL
 * call sites and comparing it in BOTH directions — a new site with no entry is red, and an entry
 * whose site is gone is red too. It could not retire that guard in favor of this package, because
 * the package only had the first direction, and trading a two-way check for a one-way one is not
 * adoption. This is the second direction.
 *
 * ## What counts as "still justifying something"
 *
 * Any raw-SQL call site the suite collects — a statement, a fragment, an expression, a dynamic
 * identifier — not only the two the policy rule reports on. An annotation sitting on a method whose
 * only raw SQL is a `DB::raw()` fragment is doing its job: the policy rule happens to be silent
 * there, and reporting the annotation as dead would send somebody to delete a reason that is true.
 *
 * ## Where it deliberately says nothing
 *
 * - **`policy: off`.** The duty does not apply, so there is nothing for an annotation to be stale
 *   against.
 * - **An excluded path.** A project that excluded a directory from the duty must not get findings
 *   from that directory as a consequence of excluding it.
 * - **A file with no collected data at all.** PHPStan analyses a set of paths, and an annotation in
 *   a file the run never opened has no evidence either way. This rule reads only files the run
 *   produced justifications for, so the case cannot arise — stated because "the run did not look"
 *   and "the run looked and found nothing" are the distinction this whole package is built on.
 *
 * @implements Rule<CollectedDataNode>
 */
final readonly class StaleRawSqlReasonRule implements Rule
{
    /** The id this rule reports under, in the package's own scheme. */
    public const string RULE_ID = 'SEC.INJ.RAW_SQL_REASON_STALE';

    /** The identifier PHPStan reports it under — the second vocabulary, as with every analyse rule. */
    public const string IDENTIFIER = 'sqlens.rawSql.staleReason';

    /**
     * The collectors whose rows count as "this annotation is still covering raw SQL".
     *
     * All five, deliberately. The policy rule reports on two of them; an annotation is doing its job
     * if it covers any raw SQL the suite can see, and narrowing this list to the reporting pair
     * would call a true reason dead.
     *
     * @var list<class-string>
     */
    private const array CALL_SITES = [
        RawSqlCallCollector::class,
        RawSqlConnectionCallCollector::class,
        RawSqlPdoCallCollector::class,
        RawSqlFragmentCollector::class,
        RawSqlExpressionCollector::class,
        DynamicIdentifierCollector::class,
    ];

    public function __construct(private AnalyseConfig $config = new AnalyseConfig) {}

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    /** @return list<IdentifierRuleError> */
    public function processNode(Node $node, Scope $scope): array
    {
        if (! $this->config->asksForAReason()) {
            return [];
        }

        $scopes = $this->coveredScopes($node);
        $lines = $this->coveredLines($node);
        $errors = [];

        foreach ($node->get(JustificationCollector::class) as $file => $perFile) {
            if (! $this->config->covers((string) $file)) {
                continue;
            }

            foreach ($perFile as $entry) {
                // The array test rides IN the loop condition rather than as an early `continue`,
                // and the reason is the coverage floor rather than style: a collector that returned
                // null contributes no entry at all, so the skip is a branch no run can enter — and
                // an unenterable branch is a line no test can honestly close. Its sibling in
                // UnjustifiedRawSqlRule is written the same way for the same reason.
                foreach (is_array($entry) ? $entry['names'] : [] as $index => $name) {
                    if ($this->nameCoversSomething($name, $scopes)) {
                        continue;
                    }

                    /** @var array{names: list<string>, lines: list<int>} $entry */
                    $errors[] = $this->finding((string) $file, $entry['lines'][$index] ?? 0, sprintf('on %s', $name));
                }
            }
        }

        foreach ($node->get(JustificationSpanCollector::class) as $file => $perFile) {
            if (! $this->config->covers((string) $file)) {
                continue;
            }

            foreach ($perFile as $span) {
                // `rawSql` only: a span carrying just an `interpolation:` answer is not a policy
                // justification, so reporting it as a stale one would name an argument the author
                // never wrote. The two channels are separate everywhere, including here.
                if (! is_array($span) || $span['rawSql'] !== true || $this->spanCoversSomething((string) $file, $span, $lines)) {
                    continue;
                }

                $errors[] = $this->finding((string) $file, $span['from'], 'here');
            }
        }

        return $errors;
    }

    /**
     * Is any collected raw-SQL call site attributed to this name, or to a method of it?
     *
     * The mirror of the policy rule's own join, run the other way round: there a call site looks for
     * a name, here a name looks for a call site. Written out rather than shared, because the two
     * differ in the direction of the prefix test — a class-level annotation is kept alive by a call
     * in ANY of its methods, while a call is justified by its own class.
     *
     * @param  list<string>  $scopes
     */
    private function nameCoversSomething(string $name, array $scopes): bool
    {
        return array_any(
            $scopes,
            static fn (string $reported): bool => $reported === $name || str_starts_with($reported, $name.'::'),
        );
    }

    /**
     * Does any collected raw-SQL call site in this file fall inside the span?
     *
     * @param  array{from: int, to: int}  $span
     * @param  array<string, list<int>>  $lines
     */
    private function spanCoversSomething(string $file, array $span, array $lines): bool
    {
        return array_any(
            $lines[$file] ?? [],
            static fn (int $line): bool => $line >= $span['from'] && $line <= $span['to'],
        );
    }

    /**
     * Every scope name a raw-SQL call site reported itself under.
     *
     * @return list<string>
     */
    private function coveredScopes(CollectedDataNode $node): array
    {
        $scopes = [];

        foreach (self::CALL_SITES as $collector) {
            foreach ($node->get($collector) as $perFile) {
                foreach ($perFile as $call) {
                    // Only the null is a real question here: every collector in the list above
                    // declares `scope` as `string|null`, and a call outside a class reports null.
                    if ($call['scope'] !== null) {
                        $scopes[] = $call['scope'];
                    }
                }
            }
        }

        return $scopes;
    }

    /**
     * Every line a raw-SQL call site sits on, per file.
     *
     * @return array<string, list<int>>
     */
    private function coveredLines(CollectedDataNode $node): array
    {
        $lines = [];

        foreach (self::CALL_SITES as $collector) {
            foreach ($node->get($collector) as $file => $perFile) {
                foreach ($perFile as $call) {
                    $lines[(string) $file][] = $call['line'];
                }
            }
        }

        return $lines;
    }

    /** The finding, worded so a reader knows the annotation is the subject rather than the code. */
    private function finding(string $file, int $line, string $where): IdentifierRuleError
    {
        return RuleErrorBuilder::message(sprintf(
            'This #[RawSql] reason %s justifies no raw SQL any more. An exemption that outlives its '
            .'reason reads for years as a decision somebody weighed, and the next reader trusts it. '
            .'Delete the attribute, or move it to the code that still runs raw SQL.',
            $where,
        ))
            ->file($file)
            ->line($line)
            ->identifier(self::IDENTIFIER)
            ->tip(sprintf(
                'Counted against EVERY raw-SQL call site this suite collects, not only the ones the '
                .'policy rule reports — a reason covering a DB::raw() fragment is doing its job. '
                .'Policy mode: %s. %s',
                $this->config->policy->value,
                RuleDocumentationUrl::for(self::RULE_ID),
            ))
            ->build();
    }
}
