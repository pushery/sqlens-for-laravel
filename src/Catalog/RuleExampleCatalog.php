<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Capture\CaptureFindingCatalog;
use Pushery\SQLens\Rules\RuleExampleEntry;
use Pushery\SQLens\Rules\RuleExamples;

/**
 * Every bad/good example this package ships, from BOTH places they live.
 *
 * ## Why there are two places, and why joining them was overdue
 *
 * `resources/data/rule-examples.json` holds 147 of them — every `rule` and every `analyse` id. The
 * ten `capture` ids carry theirs as constructor arguments on {@see CaptureRuleMetadata}, next to the
 * producer that emits the finding, and they are REQUIRED there: a capture producer cannot be
 * declared without a pair.
 *
 * ⚠️ **Nothing read the second set.** Measured before this class existed: `badExample` and
 * `goodExample` had no reader anywhere in `src/`, and `ExplainRuleTool` — the tool whose whole job
 * is turning a rule id into something actionable — answered `registered: false` for all ten,
 * because it read the JSON register alone. The examples were written, they are good, and an agent
 * asking about `CAP.PRESCAN.SIDE_EFFECT` was told none existed.
 *
 * ## What this class does NOT do
 *
 * It does not move them. The JSON register's own `about` text argues that examples belong in data
 * so they can be reviewed as a list, and that argument is sound — but relocating ten pairs is a
 * different change with a different risk, and it would be made here as a side effect of fixing a
 * missing reader. The join is the repair; where the examples ultimately live is a separate question.
 */
final readonly class RuleExampleCatalog
{
    /**
     * @param  array<string, array{bad: string, good: string}>  $captured  keyed by rule id
     */
    private function __construct(
        private RuleExamples $registered,
        private array $captured,
    ) {}

    public static function shipped(): self
    {
        $captured = [];

        foreach (CaptureFindingCatalog::metadata() as $metadata) {
            $captured[$metadata->id] = ['bad' => $metadata->badExample, 'good' => $metadata->goodExample];
        }

        return new self(RuleExamples::bundled(), $captured);
    }

    /** Whether an id has a pair at all, wherever it lives. */
    public function has(string $ruleId): bool
    {
        return $this->registered->has($ruleId) || array_key_exists($ruleId, $this->captured);
    }

    /**
     * The pair for an id, in the shape a consumer renders.
     *
     * A class-carried pair has no `note` and no `false_positives`, and they come back null rather
     * than as an invented sentence. The fields mean different things — "this rule's author has not
     * written down where it cries wolf" is a fact worth reporting, and filling the gap with a
     * paraphrase of the summary would report a different one.
     *
     * @return array{language: string, bad: string, good: string, note: string|null, false_positives: string|null}|null
     */
    public function for(string $ruleId): ?array
    {
        $entry = $this->registered->for($ruleId);

        if ($entry instanceof RuleExampleEntry) {
            return [
                'language' => $entry->language,
                'bad' => $entry->bad,
                'good' => $entry->good,
                'note' => $entry->note,
                'false_positives' => $entry->falsePositives,
            ];
        }

        $captured = $this->captured[$ruleId] ?? null;

        if ($captured === null) {
            return null;
        }

        return [
            // Always a migration body: a capture producer judges what a migration DID, so there is
            // no configuration line or shell invocation among them.
            'language' => RuleExampleEntry::LANGUAGE_PHP,
            'bad' => $captured['bad'],
            'good' => $captured['good'],
            'note' => null,
            'false_positives' => null,
        ];
    }
}
