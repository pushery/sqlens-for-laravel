<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp\Tools;

use Illuminate\Contracts\JsonSchema\JsonSchema;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use Laravel\Mcp\Server\Attributes\Name;
use Override;
use Pushery\SQLens\Agent\Mcp\RuleCatalog;
use Pushery\SQLens\Agent\Mcp\ToolAnswer;
use Pushery\SQLens\Catalog\RuleExampleCatalog;

/**
 * `explain_rule` — what a rule is, so an agent understands it before it tries to work around one.
 *
 * ## Shipped artifacts, and only shipped ones
 *
 * The answer comes from the shipped rule registry — the same artifact the documentation pages and
 * the agent-rules export are built from — joined with the shipped example register, which is what
 * the documentation pages show. Not a text file maintained beside either: two descriptions of one
 * rule drift, and the one an agent reads would be the one nobody re-reads.
 *
 * Two files rather than one is not two sources. Each is generated, each is reviewed as a diff, and
 * each is held to the rule objects by its own guard; joining them here is what makes an explanation
 * complete instead of making it a third description.
 *
 * ## An unknown id is an ERROR
 *
 * Never an empty object. An agent handed `{}` for a rule id that does not exist will explain the
 * rule away to itself — it asked, it got an answer shaped like an answer, and nothing said the
 * question was wrong. So the refusal names what was asked for and offers the ids closest to it.
 *
 * ## It reaches nothing
 *
 * No database: rule metadata is static. No network: the documentation URL is REPORTED, never
 * fetched — a tool that quietly made an HTTP request would be doing work on a machine that may have
 * no route out, and would make the same question answerable differently depending on the network.
 */
#[Name('explain_rule')]
final class ExplainRuleTool extends SqlensTool
{
    /**
     * What this tool promises, as the phrase in the description mapped to the fields that carry it.
     *
     * ## Why the sentence is DERIVED rather than written
     *
     * The description is what an agent reads in `tools/list` before it ever calls anything, so a
     * promise made there is acted on. It used to be a hand-written string, and it ended with "and
     * its own examples" over an answer that carried none — 126 of the 202 rules had one registered,
     * and not one of them reached a caller. Nothing went red, because nothing compared the sentence
     * to the answer: the phrase appeared exactly once in the whole repository, in the property
     * that declared it.
     *
     * Two hand-maintained halves that must agree is the shape this package keeps paying for. So
     * there is one half: the sentence is built from these keys, and a guard holds every listed
     * field against a real answer. A promise that cannot be kept is now unwritable rather than
     * merely discouraged.
     *
     * @var array<string, list<string>>
     */
    private const array PROMISED = [
        'category' => ['category'],
        'level' => ['level'],
        'severity' => ['severity'],
        'version window' => ['min_version', 'max_version'],
        'downtime class' => ['downtime_class'],
        'stability' => ['stability'],
        'documentation URL' => ['documentation_url'],
        'worked examples' => ['examples'],
    ];

    private ?RuleExampleCatalog $examples = null;

    public function __construct(private readonly RuleCatalog $catalog = new RuleCatalog) {}

    #[Override]
    public function description(): string
    {
        return 'Explains one SQLens rule: its '.$this->promisedPhrase()
            .'. Reads shipped metadata — no database, no network.';
    }

    public function mutating(): bool
    {
        return false;
    }

    public function handle(Request $request): Response
    {
        // Validated against the DECLARED rules, and that is measured rather than cautious: the SDK
        // publishes `inputSchema` in `tools/list` and does not check a single argument against it
        // on the way in. A missing required field and a wrongly typed one both arrive.
        $validated = $this->validated($request);

        $ruleId = is_string($validated['rule_id'] ?? null) ? $validated['rule_id'] : '';
        $rule = $this->catalog->find($ruleId);

        if ($rule === null) {
            $suggestions = $this->catalog->closestTo($ruleId);

            // An ERROR result rather than a plain answer: nothing about the rule could be
            // established, and an agent handed an empty object explains the rule away to itself.
            return ToolAnswer::undetermined(
                sprintf(
                    'no rule is registered as "%s". %s',
                    $ruleId,
                    $suggestions === []
                        ? 'Nothing registered is close enough to suggest; call this tool with an id taken from a finding.'
                        : 'Did you mean: '.implode(', ', $suggestions).'?',
                ),
                ['rule_id' => $ruleId, 'suggestions' => $suggestions],
            )->toErrorResponse();
        }

        // The registry row and the example register are two shipped artifacts, joined HERE rather
        // than in the catalog: that class is "the shipped rule registry, read", and a second file
        // inside it would make the name a half-truth. Composing an explanation is this tool's job.
        $rule['examples'] = $this->examplesFor($ruleId);

        return ToolAnswer::of(['rule' => $rule], 'Rule '.$ruleId.' explained.')->toResponse();
    }

    /**
     * The registered example for a rule — or an absence that SAYS SO.
     *
     * The discriminator is the whole point. Omitting the key when nothing is registered would leave
     * an agent unable to tell "this rule has no example" from "the tool did not send one", and a
     * substantial minority of the catalog is genuinely in the first case. That is the same
     * distinction the handler above already draws for an unknown id, where an empty object would let
     * a caller explain the rule away to itself; a missing example without a word is that error one
     * level down.
     *
     * The count used to be written here as "76 of the 202 rules" and is not any more, because a
     * hand-counted number in prose is the half of a derived claim that rots: the catalog reached 207
     * rules and the sentence did not notice. What the population IS remains checkable — the
     * completeness gates say which families owe an example — and a number nobody can re-derive from
     * the text it sits in is worth less than the sentence without it.
     *
     * @return array<string, mixed>
     */
    private function examplesFor(string $ruleId): array
    {
        // ⚠️ THROUGH THE CATALOG, NOT THE JSON REGISTER ALONE — and the difference was ten rules.
        // The capture family carries its pairs as constructor arguments on its metadata, and this
        // tool read only the file beside them, so an agent asking about `CAP.PRESCAN.SIDE_EFFECT`
        // was told no example was registered while a good one sat in the class. Nothing was red:
        // `badExample` and `goodExample` had no reader anywhere in `src/`.
        $example = ($this->examples ??= RuleExampleCatalog::shipped())->for($ruleId);

        if ($example === null) {
            return ['registered' => false, 'reason' => 'no example is registered for this rule'];
        }

        return [
            'registered' => true,
            // Stated rather than assumed to be PHP: a server-baseline rule's example is a
            // configuration line, and an agent that pasted it into a migration would ship a syntax
            // error taking the package's word for it.
            'language' => $example['language'],
            'bad' => $example['bad'],
            'good' => $example['good'],
            // Null for a class-carried pair, which has no note field, and null where the author has
            // not written down where the rule cries wolf. Carried in both cases, because an absent
            // field and an empty one mean different things.
            'note' => $example['note'],
            'false_positives' => $example['false_positives'],
        ];
    }

    /** The promised fields as the description says them: "a, b and c". */
    private function promisedPhrase(): string
    {
        $phrases = array_keys(self::PROMISED);
        $last = array_pop($phrases);

        return implode(', ', $phrases).' and '.$last;
    }

    /**
     * One patterned string, and nothing else.
     *
     * @return array<string, list<string>>
     */
    public function rules(): array
    {
        // Patterned, not merely bounded. A rule id is uppercase letters, digits, dots and
        // underscores — 120 characters of anything else is still anything else, and the parameter
        // allowlist is right to refuse a string whose shape nobody stated.
        return ['rule_id' => ['required', 'string', 'max:120', 'regex:/^[A-Z0-9._]+$/']];
    }

    /**
     * One parameter, and nothing else.
     *
     * There is no free-text field here and there never will be — not a filter, not a query, not a
     * "context" string. The whole surface of this tool is one identifier the caller read off a
     * finding this package produced.
     *
     * @return array<string, mixed>
     */
    #[Override]
    public function schema(JsonSchema $schema): array
    {
        return [
            'rule_id' => $schema->string()
                ->description('The rule id exactly as a SQLens finding reports it, for example "PG.L4.CONSTRAINT_VALIDATION_PENDING".')
                ->required(),
        ];
    }
}
