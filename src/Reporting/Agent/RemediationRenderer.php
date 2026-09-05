<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Agent;

use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\LocationKind;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\ShippedLocale;

/**
 * The fix material, rendered into the report as something a reader can act on.
 *
 * This is the difference between "here is a problem" and "here is the safe sequence", and it is the
 * reason an agent can close the loop at all: a finding names what is wrong, and the block below it
 * names the statements, in the order they run, with the decisions still standing as decisions.
 *
 * ## Four states, and none of them is silence
 *
 * A finding either carries material, or does not, or could never have, or carried some that this
 * package refused. All four are rendered, and they read differently on purpose:
 *
 *  - **A payload** becomes numbered steps, each with what to run and what it is for.
 *  - **No payload** becomes a named line — `no remediation template for this rule` — because an
 *    absent block and a rule nobody wrote a template for look identical, and only one of them is
 *    something a reader can go and fix.
 *  - **A CATALOG finding** gets a different line, because its absence is not a gap. It judges a
 *    state read off a live database, and the seam takes a migration statement — there was never a
 *    statement to write a template against. Printing "no template" there sends a reader looking for
 *    work that does not exist, so the line says what the absence IS and what to do instead.
 *  - **A refused payload** says so, and says it was OUR defect rather than theirs. Rendering it as
 *    "no template" would file a bug in this package under the reader's own migration.
 *
 * ## It renders; it never applies
 *
 * Every block here is text. Nothing in this class or reachable from it executes SQL, writes a file,
 * or edits a migration — the sequence is applied by a person or an agent, and `sqlens:lint` is run
 * again afterwards to say whether it worked. The verification line on every payload says exactly
 * that, and the section header repeats it, because a document full of runnable-looking SQL invites
 * the opposite reading.
 *
 * ## The version travels with the material
 *
 * The schema version and its stability tier are stated once, in the document head rather than per
 * finding. A consumer parsing these blocks is parsing a contract, and a contract whose version is
 * implied is one that changes without anybody noticing.
 */
final readonly class RemediationRenderer
{
    /** The line a finding with no material carries — a named absence, greppable on purpose. */
    public const string NO_TEMPLATE = 'no remediation template for this rule';

    /**
     * The line a CATALOG finding carries instead, and the difference is a decision rather than a
     * shade of wording.
     *
     * A catalog rule judges a `SchemaObject` read out of a live database. The remediation seam takes
     * a migration statement, so no catalog rule can carry material — not because nobody wrote a
     * template, but because there is no statement to write one against. Printing NO_TEMPLATE there
     * reads as a gap somebody should go and fill, and a reader who believes it goes looking for work
     * that does not exist.
     *
     * So the absence says what it is, and says what to do instead. The remedy for a state finding is
     * a migration the reader has not written yet — and once they write it, the lint path judges it
     * before it runs, which is the sentence that turns a dead end into the next step.
     */
    public const string NO_SEQUENCE_FOR_A_STATE = 'no fix sequence — this finding is about a state, not a statement';

    /**
     * The run's translator, injected.
     *
     * Never the global `trans()` helper: that reaches for the Foundation container, which shipped
     * code here may not do — a package resolving its own translator is a package that behaves
     * differently depending on what booted it.
     */
    public function __construct(private Translator $translator) {}

    /**
     * The head line naming the contract every block below is written against.
     *
     * Stated once for the document. Per finding it would be noise; absent it would be a shape a
     * consumer has to guess the version of, and guessing wrong is silent.
     *
     * @return list<string>
     */
    public function contractLine(): array
    {
        return [
            sprintf(
                '- **Fix material:** remediation schema v%d (%s) — apply a sequence yourself, then run the command again.',
                RemediationPayload::SCHEMA_VERSION,
                RemediationPayload::STABILITY->value,
            ),
        ];
    }

    /**
     * One finding's material, as the lines that follow it in the report.
     *
     * @return list<string>
     */
    public function render(Finding $finding): array
    {
        if ($finding->remediationRefusal !== null) {
            // Our defect, said out loud. The reader's migration is not the problem, and a line that
            // did not say so would send them looking through it.
            return [
                '- **Fix material:** withheld — SQLens built a sequence for this finding and refused it as unsound.',
                '  This is a defect in SQLens, not in your migration; the finding above stands.',
                '',
            ];
        }

        if (! $finding->remediation instanceof RemediationPayload) {
            // Two different absences, and only one of them is somebody's homework. The location is
            // what tells them apart — a catalog finding was read off a live database and never had a
            // statement — so nothing new has to be threaded onto the finding to make the distinction.
            //
            // Scoped to CATALOG deliberately. A callsite finding is a third case with its own answer,
            // and giving it this line on the strength of a matching shape would be a claim nobody
            // measured.
            return $finding->location->kind === LocationKind::Catalog
                ? [
                    '- **Fix material:** '.self::NO_SEQUENCE_FOR_A_STATE.'.',
                    '  The remedy is a migration you have not written yet. Write it, and '
                    .'`sqlens:lint` judges it before it runs.',
                    '',
                ]
                : ['- **Fix material:** '.self::NO_TEMPLATE.'.', ''];
        }

        return $this->payload($finding->remediation);
    }

    /**
     * @return list<string>
     */
    private function payload(RemediationPayload $payload): array
    {
        $lines = [
            '- **Fix material:** '.$this->strategyLabel($payload->strategy)
                .($payload->debtKind !== null ? ' · opens debt: `'.$payload->debtKind.'`' : ''),
            '',
        ];

        foreach ($payload->preconditions as $precondition) {
            $lines[] = '  - _Before you start:_ '.$this->text($precondition);
        }

        if ($payload->preconditions !== []) {
            $lines[] = '';
        }

        foreach ($payload->steps as $step) {
            $lines = [...$lines, ...$this->step($step, $payload->subject)];
        }

        if ($payload->verification !== null) {
            $lines[] = '  **Then check:** '.$this->text($payload->verification);
            $lines[] = '';
        }

        return $lines;
    }

    /**
     * One step: what it is, what it is for, and — where there is one — the thing to run.
     *
     * The note comes first and the code second, deliberately. A block of SQL with its explanation
     * underneath is a block most readers run before reaching the explanation, and the whole point of
     * a `manual_gate` step is that it has no code at all.
     *
     * @return list<string>
     */
    private function step(RemediationStep $step, RemediationSubject $subject): array
    {
        $lines = [
            sprintf('  %d. **%s** — %s', $step->order, $this->kindLabel($step->kind, $subject), $this->text($step->noteKey)),
        ];

        if ($step->sqlTemplate !== null) {
            $lines = [...$lines, '', '     ```sql', '     '.$step->sqlTemplate, '     ```'];
        }

        if ($step->laravelSnippet !== null) {
            $lines = [...$lines, '', '     ```php', ...array_map(
                static fn (string $line): string => '     '.$line,
                explode("\n", $step->laravelSnippet),
            ), '     ```'];
        }

        return [...$lines, ''];
    }

    /**
     * The same material, shaped for a TERMINAL instead of a markdown document.
     *
     * A second method on this class rather than a second renderer, and the difference matters: what
     * differs between the two surfaces is the SHAPE — bold text, fenced blocks and blank lines belong
     * to the markdown report and are noise in a console — while the VOCABULARY must not differ.
     * A strategy called one thing at the terminal and another in the report would be two answers
     * to one question, and the labels live here.
     *
     * `$expanded` is the `--show-remediation` switch. Without it a finding gets ONE line, because a
     * multi-step SQL sequence printed under every finding turns a lint report into something nobody
     * reads to the end — and an unread report gates nothing. The line still says the material exists
     * and how to get it, which is the whole job of a default that hides something.
     *
     * @return list<string>
     */
    public function consoleLines(Finding $finding, bool $expanded = false): array
    {
        if ($finding->remediationRefusal !== null) {
            // Named, never silent. SQLens built a sequence and rejected its own work; a reader who
            // saw nothing here would assume no material exists and go looking through their
            // migration for a problem that is ours.
            return ['    remediation refused ('.$finding->remediationRefusal.') — a defect in SQLens, not in your migration'];
        }

        if (! $finding->remediation instanceof RemediationPayload) {
            // No line at all. An empty placeholder under a finding that never had material is a
            // blank the reader has to interpret, and most findings have none.
            return [];
        }

        $payload = $finding->remediation;

        // ⚠️ NOT `remediation=…`. The run header already carries a line spelled exactly that way —
        // `remediation=preview (schema 1)`, the CONTRACT for the whole run — and a per-finding line
        // sharing its prefix would read as a second opinion about the same thing. Two lines, two
        // shapes, because they answer two questions: what the schema is, and what this finding has.
        $hint = '    remediation available ('.RemediationPayload::STABILITY->value.'): '.$this->strategyLabel($payload->strategy)
            .($payload->debtKind !== null ? ' · opens debt: '.$payload->debtKind : '');

        if (! $expanded) {
            return [$hint.' — pass --show-remediation, or read it in --format=json'];
        }

        $lines = [$hint];

        foreach ($payload->preconditions as $precondition) {
            $lines[] = '      before you start: '.$this->text($precondition);
        }

        foreach ($payload->steps as $step) {
            $lines[] = sprintf('      %d. %s — %s', $step->order, $this->kindLabel($step->kind, $payload->subject), $this->text($step->noteKey));

            if ($step->sqlTemplate !== null) {
                // Indented one level further and never fenced: a terminal has no code block, and a
                // reader copying this out must get the statement and nothing decorative with it.
                $lines[] = '         '.$step->sqlTemplate;
            }
        }

        if ($payload->verification !== null) {
            $lines[] = '      then check: '.$this->text($payload->verification);
        }

        return $lines;
    }

    /**
     * A step kind as a reader meets it, rather than as the schema spells it.
     *
     * ## Two vocabularies, because the reader is in two different situations
     *
     * A statement payload rewrites something in front of the reader: "in this migration" and "in a
     * later migration" both point at files that exist. A state payload points at nothing — the
     * finding came from reading a database, and the fix is a migration nobody has written. "In a
     * later migration" there quietly implies an earlier one.
     *
     * ⚠️ THE SUBJECT COMES FROM THE PAYLOAD, never from a shape this renderer recognizes. Exactly
     * one place knows which of the two a template is about, and it is the field the producer set. A
     * renderer that inferred it — from the location kind, from the step kind, from whether a step
     * carries SQL — would be a second answer to a question that already has one, and two answers
     * drift.
     *
     * `MigrationStatement` is listed in the state arm rather than defaulted, and it is unreachable
     * there: the validator refuses that kind on a state payload. A `default` would silently hand it
     * the lint wording, which is the one outcome this method exists to prevent.
     */
    private function kindLabel(RemediationStepKind $kind, RemediationSubject $subject): string
    {
        if ($subject === RemediationSubject::SchemaObject) {
            return match ($kind) {
                RemediationStepKind::SeparateMigration => 'In a new migration',
                RemediationStepKind::QueuedJob => 'In a queued job',
                RemediationStepKind::SessionSetting => 'Session setting',
                RemediationStepKind::MigrationStatement,
                RemediationStepKind::ManualGate => 'Decide first',
            };
        }

        return match ($kind) {
            RemediationStepKind::MigrationStatement => 'In this migration',
            RemediationStepKind::SeparateMigration => 'In a later migration',
            RemediationStepKind::QueuedJob => 'In a queued job',
            RemediationStepKind::SessionSetting => 'Session setting',
            RemediationStepKind::ManualGate => 'Decide first',
        };
    }

    /**
     * The strategy as a sentence.
     *
     * `none` gets its own wording, and the difference is the point: it is a CONCLUSION, not a gap.
     * Labeling it "none" beside the others would read as the absent case above, which is exactly
     * the distinction the value exists to preserve.
     */
    private function strategyLabel(RemediationStrategy $strategy): string
    {
        return $strategy === RemediationStrategy::None
            ? 'no safe standard sequence — read the reason below and decide'
            : 'the `'.$strategy->value.'` sequence, in this order';
    }

    /**
     * A catalog key as the reader's own language.
     *
     * Falls back to the key itself, which is ugly and honest: a missing translation shows up as
     * something obviously wrong rather than as a blank line, and a blank line beside a numbered step
     * is a step that looks like it needs no explanation.
     */
    private function text(string $key): string
    {
        $translated = $this->translator->get($key, [], ShippedLocale::CODE);

        return is_string($translated) ? $translated : $key;
    }
}
