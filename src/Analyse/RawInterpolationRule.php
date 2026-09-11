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
use Pushery\SQLens\Subjects\ParametrizationSignal;

/**
 * A runtime value was assembled into the text of a SQL statement.
 *
 * ## What it reports, and what separates it from the policy rule beside it
 *
 * {@see UnjustifiedRawSqlRule} asks whether reaching for raw SQL was a decision somebody wrote down.
 * This one asks something the analyzer can see for itself: was the statement's TEXT assembled from
 * something that is not known until the program runs? An interpolated string, a concatenation, a
 * `sprintf` — the shapes where a value becomes part of the statement rather than a parameter to it.
 *
 * The two are deliberately different questions, and only this one reaches the fragment methods. A
 * `whereRaw('status = ?', [$status])` is ordinary Laravel and never reported here, because the text
 * is entirely the author's; the same call with the status interpolated into it is.
 *
 * ## It still does not read the query
 *
 * Nothing here parses SQL, and the message quotes none of it. What the rule knows is the SHAPE the
 * text was built in — that is a syntactic observation a parser can prove. Whether the resulting
 * statement is exploitable depends on what the value contains at runtime, which is taint analysis,
 * which this package does not do at any point. The finding says what it saw and names the limit.
 *
 * `undetermined` is not reported. A call site the classifier could not read is not evidence of
 * interpolation, and reporting doubt as a high-severity finding is how a security rule teaches a
 * team to ignore it. The undetermined ones are carried in the collected data for a report to show
 * as what they are — a check that could not answer — rather than being silently dropped.
 *
 * @implements Rule<CollectedDataNode>
 */
final class RawInterpolationRule implements Rule
{
    /**
     * The id this rule reports under.
     *
     * `SEC.INJ.` is the injection area — the only security area whose subject is PHP source rather
     * than a live server. Its metadata lives in {@see AnalyseRuleCatalog}, which is what puts the id
     * in the shipped catalog; a rule that reports under an id no catalog carries is one nobody can
     * look up, baseline, or read a page about.
     */
    public const string RULE_ID = 'SEC.INJ.RAW_INTERPOLATION';

    /**
     * The identifier PHPStan reports this rule under — a SECOND vocabulary, and the reason the
     * catalog carries it.
     *
     * PHPStan owns the identifier namespace of its own output: `--error-format=json` gives a
     * consumer this string and never {@see self::RULE_ID}. Without the catalog carrying both, a
     * machine reading that JSON has no way to reach the severity, category or level the registry
     * holds — it would have to hard-code the mapping this constant makes readable.
     */
    public const string IDENTIFIER = 'sqlens.rawSql.interpolation';

    public function getNodeType(): string
    {
        return CollectedDataNode::class;
    }

    /** @return list<IdentifierRuleError> */
    public function processNode(Node $node, Scope $scope): array
    {
        $errors = [];

        // All four collectors, because the same defect reaches the database through all four
        // shapes: the facade, a builder fragment, a connection instance, and `DB::raw()`. The third
        // was added after measuring that `$connection->statement("… {$value} …")` produced no
        // finding at all; the fourth after measuring the same of `DB::raw("… '{$value}'")`, which
        // sat in none of the vocabulary's three lists and so was collected by nobody.
        //
        // The expression collector is deliberately NOT read by the policy rule beside this one —
        // see its class docblock. Requiring a written justification for every `DB::raw('count(*)')`
        // is how an analyse suite gets switched off in its first week.
        // The hatch, and it is a SEPARATE channel from the policy rule's — `#[RawSql(interpolation:
        // '…')]`, never `reason:`. A method reasoned "we need a window function" has said nothing
        // about an interpolated value inside it, and reading one as the other would switch this rule
        // off wherever the policy annotation is on.
        //
        // Why the rule accepts an annotation at all, having refused one until now: where no binding
        // form EXISTS the remedy this rule prints cannot be followed. No engine binds an identifier,
        // a schema name or a DDL fragment — measured with a positive control, `SELECT 1 FROM ?` is a
        // syntax error where `SELECT ? FROM migrations` runs. The only answer left was a PHPStan
        // `ignoreErrors` entry, which carries no reason and is scoped by PATH: the next
        // interpolation in that file, one that DOES have a binding available, is silenced with it.
        // An annotation is at the call site, carries the sentence, and covers what it sits on.
        $justified = JustificationCoverage::interpolation($node);

        foreach ([RawSqlCallCollector::class, RawSqlFragmentCollector::class, RawSqlConnectionCallCollector::class, RawSqlPdoCallCollector::class, RawSqlExpressionCollector::class] as $collector) {
            foreach ($node->get($collector) as $file => $calls) {
                foreach ($calls as $call) {
                    if ($call['signal'] !== ParametrizationSignal::Interpolated->value) {
                        continue;
                    }

                    if ($justified->covers($call['scope'] ?? null, (string) $file, $call['line'])) {
                        continue;
                    }

                    $errors[] = $this->finding((string) $file, $call);
                }
            }
        }

        return $errors;
    }

    /**
     * What to do about it — and NOT the same sentence for every sink.
     *
     * Nine of the ten fragment sinks take a bindings array, so "pass it as a binding" is advice the
     * reader can act on and the shape is worth showing. `raw()` takes one argument and nothing else,
     * so the same sentence would prescribe a call the framework does not offer. A tool that answers
     * a real finding with an impossible fix reads as one that did not understand the code, and the
     * next finding it makes is believed less.
     *
     * The set is {@see RawSqlSinks::SINKS_WITHOUT_BINDINGS}, which is derived from the installed
     * framework by reflection rather than typed — so a Laravel that gives `raw()` bindings moves the
     * advice back without anybody editing this method.
     */
    private function remedy(string $method, bool $identifierQuoted): string
    {
        // The value already went through the engine's identifier quoting, and that changes what can
        // honestly be asked of the author. Every sentence below tells them to bind the value; no
        // engine binds an identifier, a schema name or a DDL fragment — measured with a positive
        // control, `SELECT 1 FROM ?` is a syntax error where `SELECT ? FROM migrations` runs. So the
        // advice would be impossible to follow, which this method's own docblock names as the way a
        // tool loses its reader.
        //
        // The finding STAYS, and the sentence says why rather than pretending the value is gone:
        // `wrap()` prevents the breakout and not the object choice — `wrap('other_schema.secrets')`
        // yields `"other_schema"."secrets"`, measured. So the remaining question is not escaping,
        // it is which objects the value is allowed to name, and that is answerable.
        if ($identifierQuoted) {
            return 'The value goes through the connection\'s grammar, so it cannot break out of the '
                .'identifier quoting — but it still chooses WHICH object the statement addresses, and '
                .'a value carrying a dot reaches across schemas. Constrain it to a set you wrote '
                .'(an enum, a match, a constant map) rather than passing it through; no engine binds '
                .'an identifier, so a list is the only place that decision can live.';
        }

        if (in_array($method, RawSqlSinks::SINKS_WITHOUT_BINDINGS, true)) {
            // Two sinks take no bindings, and the way out of each is different — so the sentence is
            // chosen by FAMILY rather than by name. A branch on `unprepared` would be the
            // hand-kept exception that is missing again at the next argument-less member.
            //
            // A fragment sits inside a builder call that does take bindings, so the value has a
            // place to go. A statement has no such neighbor in the same expression: it IS the
            // whole statement, and `unprepared()` runs it with no prepared statement at all, which
            // is why naming the prepared sibling matters more here than anywhere else.
            return in_array($method, RawSqlSinks::STATEMENT_SINKS, true)
                ? sprintf(
                    '%s() takes no bindings and runs the string as given — there is no prepared '
                    .'statement behind it at all. Use the prepared form instead: DB::statement(\'… = '
                    .'?\', [$value]) takes the same values and keeps them out of the text.',
                    $method,
                )
                : sprintf(
                    '%s() takes no bindings, so this call has no placeholder form. Move the value to '
                    .'the builder method that receives the expression — it does take one — instead '
                    .'of assembling it here.',
                    $method,
                );
        }

        return sprintf(
            'Pass it as a binding instead — the placeholder form takes the same values and keeps them '
            .'out of the statement: %s(\'… = ?\', [$value]).',
            $method,
        );
    }

    /**
     * @param  array{method: string, line: int, origin: string, ...}  $call
     */
    private function finding(string $file, array $call): IdentifierRuleError
    {
        return RuleErrorBuilder::message(sprintf(
            'A runtime value is assembled into the text of this statement (%s, through %s()). %s',
            $this->shape($call['origin']),
            $call['method'],
            $this->remedy($call['method'], ($call['quoted'] ?? false) === true),
        ))
            ->file($file)
            ->line($call['line'])
            ->identifier(self::IDENTIFIER)
            ->tip(
                'Syntactic pattern, not taint analysis: SQLens never reads the query text and makes no '
                .'claim about whether this value is attacker-controlled. It reports that the value '
                .'reached the STATEMENT rather than the parameters, which is the property that decides '
                .'whether it could ever matter.'
                // Where a binding form does not EXIST — an identifier, a schema name, DDL assembled
                // from an enum — the remedy above cannot be followed, because PostgreSQL takes no
                // parameter in those positions. Without naming the way out, the only remaining
                // moves are to stop running the rule or to stop running the analyzer, and a project
                // that reaches for either loses the findings it could have acted on. So the
                // structural case is named, with PHPStan's own mechanism and the identifier this
                // rule emits — built from the constant, never typed, so a renamed identifier cannot
                // leave a wrong one printed here.
                .' Where no binding form exists — an identifier, a schema name, DDL built from an '
                .'enum — the remedy above does not apply. Say so at the call site with '
                .'#[RawSql(interpolation: \'…\')], which covers what it sits on and carries the '
                .'sentence; a PHPStan ignoreErrors entry with identifier: '.self::IDENTIFIER
                .' is the coarser fallback, because it is scoped by path and states no reason. '
                .'analyse.exclude_paths deliberately does not reach this rule.'
                .' '.RuleDocumentationUrl::for(self::RULE_ID)
            )
            ->build();
    }

    /**
     * The assembly shape, in words a reader can go and look for.
     *
     * Named rather than quoted: the message must never carry SQL text, because a finding travels
     * into CI logs, SARIF files and agent artifacts, and a query fragment reproduced there is a
     * second copy of whatever the statement touched.
     */
    private function shape(string $origin): string
    {
        return match ($origin) {
            'interpolation' => 'string interpolation',
            'concatenation' => 'concatenation or a string builder',
            default => 'a non-constant expression',
        };
    }
}
