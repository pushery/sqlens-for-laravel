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
 * A column or a sort direction taken from the request.
 *
 * ## Why this is not the interpolation rule with a different subject
 *
 * A value can be bound; an identifier cannot. `whereRaw('status = ?', [$status])` keeps the value
 * out of the statement — there is no equivalent for `orderBy($column)`, because the column name IS
 * part of the statement's grammar. So the advice differs, and that is the whole reason for a second
 * rule: the raw-SQL rules say *bind it*, and here the only safe answer is *choose from a list you
 * wrote*.
 *
 * ## What it reports, and the line it will not cross
 *
 * It reports a call whose column or direction is **both** not known at analysis time **and**
 * visibly reaching the HTTP request.
 *
 * Both halves are load-bearing. Not-known alone is the normal state of every sortable listing ever
 * written, so a rule built on it would be the loudest thing in the package and would be muted in
 * its first week — taking the real findings with it. Request-origin alone says nothing either: a
 * request value that has passed an allowlist is a constant string, and the classifier says so.
 *
 * When the value is unknown and the request is NOT visible, the finding is `undetermined` with
 * {@see UndeterminedReason::IdentifierOriginUnresolved} — reported as a check that could not answer,
 * never as a pass. The allowlist may well be one method away, and this rule sees one expression in
 * one scope; saying so is the only honest reading.
 *
 * @implements Rule<CollectedDataNode>
 */
final class DynamicIdentifierRule implements Rule
{
    /** The id this rule reports under; its metadata lives in {@see AnalyseRuleCatalog}. */
    public const string RULE_ID = 'SEC.INJ.DYNAMIC_IDENTIFIER';

    /**
     * The identifier PHPStan reports this rule under — a SECOND vocabulary, and the reason the
     * catalog carries it.
     *
     * PHPStan owns the identifier namespace of its own output: `--error-format=json` gives a
     * consumer this string and never {@see self::RULE_ID}. Without the catalog carrying both, a
     * machine reading that JSON has no way to reach the severity, category or level the registry
     * holds — it would have to hard-code the mapping this constant makes readable.
     */
    public const string IDENTIFIER = 'sqlens.rawSql.dynamicIdentifier';

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    /** @return list<IdentifierRuleError> */
    public function processNode(Node $node, Scope $scope): array
    {
        $errors = [];

        foreach ($node->get(DynamicIdentifierCollector::class) as $file => $calls) {
            foreach ($calls as $call) {
                if (! $call['fromRequest']) {
                    continue;
                }

                $errors[] = $this->finding((string) $file, $call);
            }
        }

        return $errors;
    }

    /**
     * @param  array{method: string, line: int, ...}  $call
     */
    private function finding(string $file, array $call): IdentifierRuleError
    {
        return RuleErrorBuilder::message(sprintf(
            'A column or sort direction reaching %s() comes from the HTTP request. An identifier is '
            .'part of the statement, not a value, so it cannot be bound — the fix is an allowlist: '
            .'compare the input against columns you wrote and pass one of those.',
            $call['method'],
        ))
            ->file($file)
            ->line($call['line'])
            ->identifier(self::IDENTIFIER)
            ->tip(
                'Any of these silences it, because each leaves the analyzer with a value that can only '
                .'be one of the strings you wrote: an in_array($input, [\'name\', \'created_at\'], true) '
                .'guard, a match over constants, or a lookup into a constant map. Escaping is not an '
                .'option here — identifiers have no binding form.'
                .' '.RuleDocumentationUrl::for(self::RULE_ID)
            )
            ->build();
    }
}
