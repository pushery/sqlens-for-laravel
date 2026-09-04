<?php

declare(strict_types=1);

namespace Pushery\SQLens\Analyse;

use PhpParser\Node;
use PHPStan\Analyser\Scope;
use PHPStan\Node\CollectedDataNode;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use Pushery\SQLens\Attributes\SqlensIgnore;
use Pushery\SQLens\Rules\RuleDocumentationUrl;

/**
 * Raw SQL that nobody wrote a reason for.
 *
 * ## What it asks, and what it deliberately does not
 *
 * It asks one question: *is there a written reason for this call site?* It does **not** ask whether
 * the SQL is dangerous, whether its values are bound, or where they came from. That is not modesty
 * about the implementation — it is the design. Deciding "is this SQL safe" from the call site is
 * taint analysis, this package does not do taint analysis, and a rule that implied otherwise would
 * be making a promise its author knows it cannot keep.
 *
 * The bet behind a justification requirement is different and much smaller: raw SQL is sometimes
 * genuinely the right tool, and a project that has to say WHY out loud writes less of it by
 * accident. The reason is for the next reader, not for this rule — nothing here parses it.
 *
 * ## Honest limits, stated where a reader will meet them
 *
 * - **A class-level annotation covers every call in the class.** That is the coarse end of the
 *   mechanism and it is a choice a project makes: the method-level form exists precisely so a class
 *   with one reasoned raw statement and one careless one does not excuse both.
 * - **Syntactic detection only.** A call reached through a variable, a callable string or a
 *   container binding is invisible here. The collector says as much in its own terms; what matters
 *   is that this rule reports what it SAW and never claims the rest is clean.
 * - **A suppression whose rule ids are not literal strings does not suppress.** Reading them would
 *   mean evaluating project code during analysis. The finding stays visible instead, which is the
 *   safe direction.
 *
 * ## Who constructs it, and who merely reads it
 *
 * PHPStan does — from the shipped `extension.neon`, the same inversion as a service provider. No
 * caller in `src/` instantiates this class, and one would mean the package had started running its
 * own analyzer.
 *
 * {@see AnalyseRuleCatalog} reads {@see self::RULE_ID} and nothing else. That is not a caller in the
 * sense above: it is the catalog taking the id from its one owner instead of repeating the literal.
 * The rule shipped without that link and was consequently in no catalog at all — unlistable,
 * unexplainable and unbaselineable, with an id nothing had ever put through the format contract.
 *
 * @implements Rule<CollectedDataNode>
 */
final readonly class UnjustifiedRawSqlRule implements Rule
{
    /**
     * The id this rule reports under.
     *
     * It follows the package's own scheme rather than PHPStan's dotted identifiers, because the id a
     * user reads in a report has to be the id they can act on — two vocabularies for one rule is how
     * a suppression comes to be written for something that does not exist.
     *
     * Note that a project does NOT write this id to accept a call site. Acceptance is
     * `#[RawSql(reason: '…')]`, which names no rule at all: it answers this rule's question rather
     * than silencing it. Naming the id is what {@see SqlensIgnore} is for, and that is a different
     * statement — the finding is produced and recorded as suppressed.
     */
    public const string RULE_ID = 'SEC.INJ.RAW_SQL_WITHOUT_REASON';

    /**
     * The identifier PHPStan reports this rule under — a SECOND vocabulary, and the reason the
     * catalog carries it.
     *
     * PHPStan owns the identifier namespace of its own output: `--error-format=json` gives a
     * consumer this string and never {@see self::RULE_ID}. Without the catalog carrying both, a
     * machine reading that JSON has no way to reach the severity, category or level the registry
     * holds — it would have to hard-code the mapping this constant makes readable.
     */
    public const string IDENTIFIER = 'sqlens.rawSql.unjustified';

    /**
     * The run's policy — the ONLY rule in this suite that reads it.
     *
     * Deliberately not shared with the injection rules. This one reports a missing sentence; those
     * report that a runtime value reached the statement text, and severity is not level-gated in
     * this package by design. A configuration line able to silence them would let one line of neon
     * disable half the security surface, so the line is drawn here — at the class that asks a
     * policy question — rather than at a shared base every rule would inherit.
     */
    public function __construct(private AnalyseConfig $config = new AnalyseConfig) {}

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    /** @return list<IdentifierRuleError> */
    public function processNode(Node $node, Scope $scope): array
    {
        // `policy: off` — the duty does not apply, so there is nothing to report. The injection
        // rules are separate services and are not reached from here at all.
        if (! $this->config->asksForAReason()) {
            return [];
        }

        $justified = $this->justifiedNames($node);
        $errors = [];

        // Both spellings of the same decision. `DB::statement(…)` and
        // `DB::connection('x')->statement(…)` hand the database the same raw text, and a rule that
        // asked for a reason on one and not the other would be answerable by changing the spelling.
        // The prefix travels with the collector so the message names the call the reader wrote.
        $sources = [
            RawSqlCallCollector::class => 'DB::',
            RawSqlConnectionCallCollector::class => '$connection->',
        ];

        foreach ($sources as $collector => $prefix) {
            foreach ($node->get($collector) as $file => $calls) {
                // Excluded paths are skipped for the POLICY question only, and the file is tested
                // once per file rather than once per call: the answer cannot differ between two
                // calls in one file, and asking again would make the cost of an exclusion list
                // proportional to the call sites rather than to the files.
                if (! $this->config->covers((string) $file)) {
                    continue;
                }

                foreach ($calls as $call) {
                    if ($this->isJustified($call['scope'], $justified)) {
                        continue;
                    }

                    $errors[] = RuleErrorBuilder::message(sprintf(
                        'Raw SQL through %s%s() with no written reason. Raw SQL is sometimes the right '
                        .'tool; this rule asks only that the choice be stated, so the next reader does not '
                        .'have to reconstruct it. Answer it with #[RawSql(reason: \'…\')] on the method or '
                        .'the class — the reason is mandatory, and an empty one does not count.',
                        $prefix,
                        $call['method'],
                    ))
                        ->file((string) $file)
                        ->line($call['line'])
                        ->identifier(self::IDENTIFIER)
                        ->tip(sprintf(
                            'This does NOT say the SQL is unsafe — SQLens does no taint analysis and this '
                            .'rule never looks at the query text. It says nobody wrote down why raw SQL was '
                            // The active mode travels with the finding, so a CI log says which
                            // question was actually asked. Without it, a report read weeks later
                            // cannot be told apart from one produced under a different setting —
                            // and `strict` and `documented` disagree about exactly these lines.
                            .'chosen here. Policy mode: %s. %s',
                            $this->config->policy->value,
                            RuleDocumentationUrl::for(self::RULE_ID),
                        ))
                        ->build();
                }
            }
        }

        return $errors;
    }

    /**
     * Is this call site covered by a justification?
     *
     * A call in `App\\Report::build()` is justified by an annotation on the method OR on the class,
     * so both names are tried. Outside a class there is nothing an attribute could sit on, and the
     * call reports — which is correct rather than harsh: a raw statement at file scope has no place
     * to carry its reasoning either.
     *
     * "Outside a class" means a free function, file scope or a closure. It does NOT mean an
     * anonymous class, and reading it that way was a real defect: an anonymous class IS a
     * class, it has methods, the attribute is syntactically placeable on both, and PHPStan gives it
     * a name that both sides of this join agree on. It is also the form every Laravel migration
     * takes, so treating it as unanswerable shut the hatch precisely where raw DDL lives. See
     * {@see JustificationCollector::processNode()} for the name that makes the join work.
     *
     * @param  list<string>  $justified
     */
    private function isJustified(?string $scope, array $justified): bool
    {
        if ($scope === null) {
            return false;
        }

        if (in_array($scope, $justified, true)) {
            return true;
        }

        $class = str_contains($scope, '::') ? substr($scope, 0, (int) strpos($scope, '::')) : $scope;

        return in_array($class, $justified, true);
    }

    /**
     * Every class and method that carries a reasoned `#[RawSql]`.
     *
     * @return list<string>
     */
    private function justifiedNames(CollectedDataNode $node): array
    {
        $names = [];

        foreach ($node->get(JustificationCollector::class) as $perFile) {
            foreach ($perFile as $entry) {
                if (is_array($entry)) {
                    foreach ($entry['names'] as $name) {
                        $names[] = $name;
                    }
                }
            }
        }

        return $names;
    }
}
