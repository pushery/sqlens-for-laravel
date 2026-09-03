<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Agent;

use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\ReportedServerVersion;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\GateDecision;
use Pushery\SQLens\Severity\SeverityGate;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `--format=agent` — the whole run as ONE markdown report an agent can act on.
 *
 * ## Why a document rather than a stream
 *
 * An agent reads a report the way a person reads a ticket: once, at the top, deciding what to do
 * first. The console reporter is written for somebody watching a run; the JSON envelope for
 * something parsing it. Neither shape survives being pasted into a coding agent — the first loses
 * its structure, the second buries the three sentences that matter under a hundred fields.
 *
 * So this is one document, in the order a reader needs it: what the run was, what it found, what to
 * fix first, what it could NOT answer, and what not to do about any of it.
 *
 * ## It renders; it never decides
 *
 * Every number here is read from a decision something else already made. The gate axis and the
 * blocking verdict come from {@see GateDecision}, the same object the exit code and the JSON
 * summary read — three readers of one decision rather than three computations of it, because the
 * day they diverge is the day a report disagrees with the exit status printed beside it.
 *
 * The chosen format never changes the gate. `--format=agent` and `--format=json` over one fixture
 * end in the same exit code, and a test says so.
 *
 * ## The two axes stay apart
 *
 * Level models how pedantic a project has decided to be; severity models risk. A security finding
 * is measured by severity alone — a level-0 run still breaks on a critical one — so the counters
 * are never summed into a single number. A reader given one total cannot tell an appetite from a
 * risk, and that is the distinction the whole package is arranged around.
 *
 * ## No silent green
 *
 * `undetermined` is counted beside `pass` and `fail` in the summary rather than below it, and a run
 * that failed nothing but could not answer something is never rendered as clean. What that section
 * says in detail is its own concern; that it can never be omitted is this class's.
 */
final readonly class AgentReporter implements Reporter
{
    /**
     * @param  Redactor  $redactor  masks credential values. REQUIRED, not optional: a redactor a
     *                              caller may omit is one a caller will omit, and this is the
     *                              surface where omitting it publishes somebody's password with a
     *                              heading on it. The manager supplies it; nothing here reaches for
     *                              a container to find one, which would be the same hidden
     *                              dependency wearing a default argument.
     */
    public function __construct(
        private Redactor $redactor,
        /**
         * The fix-material renderer. REQUIRED for the same reason the redactor is, and with a
         * sharper edge: it needs the run's TRANSLATOR, and a default would have to reach for the
         * Foundation to find one — which shipped code here may not do. The manager supplies it.
         */
        private RemediationRenderer $remediation,
        private BriefingPrioritizer $prioritizer = new BriefingPrioritizer,
        private UndeterminedSection $undeterminedSection = new UndeterminedSection,
    ) {}

    public function name(): string
    {
        return 'agent';
    }

    public function report(Result $result, RunContext $context, OutputInterface $out): void
    {
        $gate = new SeverityGate($context->minSeverity);
        $level = Level::from($context->level);

        $decided = array_map(
            static fn (Finding $finding): array => [$finding, GateDecision::for($finding, $level, $gate)],
            $result->findings,
        );

        // ONE seam. The whole document is masked here rather than section by section, because a
        // redactor invoked per section is a redactor the next section can be written without — and
        // the arm that would catch that omission is the one nobody writes.
        //
        // `rtrim` because every section ends with a blank line to separate it from the next, and
        // `writeln` adds a newline of its own — so the document would end in two. That matters
        // whenever this goes to `--output`: every other artifact this package writes ends in
        // exactly one newline, and a format that ended in two would be the only one that did.
        $document = rtrim(implode("\n", [
            ...$this->heading($result, $context),
            ...$this->summary($result, $decided),
            ...$this->findings($decided),
            ...$this->undetermined($decided),
            ...$this->boundaries(),
        ]), "\n");

        $out->writeln($this->redactor->in($document));
    }

    /**
     * The run's own parameters, so a reader can tell WHICH world this is about.
     *
     * The same set the reproducibility header carries, in prose a reader skims rather than a table
     * they parse. A report about a database nobody named is advice about nothing, and the version
     * is the field that most often makes a piece of advice wrong.
     *
     * @return list<string>
     */
    private function heading(Result $result, RunContext $context): array
    {
        $servers = array_map(
            static fn (ReportedServerVersion $version): string => $version->connection.' '.$version->version,
            $context->serverVersions,
        );

        $tools = [];

        foreach ($context->toolVersions as $tool => $version) {
            $tools[] = $tool.' '.$version;
        }

        return [
            '# Database change report',
            '',
            'This is the whole run, in the order it is worth acting on. Everything below was decided by',
            'the same engine and the same gates a pipeline uses — the format changed, the verdict did not.',
            '',
            '## The run',
            '',
            '- **Mode:** '.$context->mode->value.' — '.($context->mode->value === 'shadow'
                ? 'migrations were executed against a throwaway database'
                : 'nothing was executed against a database'),
            '- **Profile:** '.$context->profile->value,
            '- **Level:** '.$context->level.' (which rules ran)',
            '- **Severity floor:** '.($context->minSeverity->value ?? 'off').' (which risks block)',
            '- **Strict tools:** '.($context->strictTools ? 'on' : 'off')
                .' · **Strict undetermined:** '.($context->strictUndetermined ? 'on' : 'off'),
            '- **Servers:** '.($servers === [] ? 'none addressed' : implode(', ', $servers)),
            '- **External tools:** '.($tools === [] ? 'none' : implode(', ', $tools)),
            '- **Suppressed:** '.count($result->suppressed).' finding(s) hidden by configuration or a baseline',
            // Read from the payload's own constant rather than written here. Two places stating a
            // maturity is how one of them keeps saying `preview` after the other stopped — and the
            // direction of that error is the bad one: a reader told `preview` about a stable
            // contract merely distrusts it, while one told `stable` about a preview builds on it.
            '- **Output stability:** '.RemediationPayload::STABILITY->value
                .' — the shape of this document may change before 1.0',
            // The contract every fix block below is written against, stated ONCE. Per finding it
            // would be noise; absent, a consumer parsing those blocks would be parsing a versioned
            // shape whose version it had to guess.
            ...$this->remediation->contractLine(),
            '',
        ];
    }

    /**
     * The counts, per axis, never summed.
     *
     * @param  list<array{0: Finding, 1: GateDecision}>  $decided
     * @return list<string>
     */
    private function summary(Result $result, array $decided): array
    {
        $status = $result->countsByStatus();

        $blockingByAxis = static fn (GateAxis $axis): int => count(array_filter(
            $decided,
            static fn (array $pair): bool => $pair[1]->blockedBy === $axis,
        ));

        return [
            '## What it found',
            '',
            '| | Count |',
            '| --- | --- |',
            '| Blocking on the level gate | '.$blockingByAxis(GateAxis::Level).' |',
            '| Blocking on the severity gate | '.$blockingByAxis(GateAxis::Severity).' |',
            '| Reported, not blocking | '.($status['pass'] + $status['fail'] - $blockingByAxis(GateAxis::Level) - $blockingByAxis(GateAxis::Severity)).' |',
            '| **Could NOT be determined** | '.$status['undetermined'].' |',
            '',
            'The two gates are separate on purpose. Level is how pedantic this project has decided to',
            'be; severity is risk, and risk is not a matter of appetite — a low-level run still breaks',
            'on a critical security finding. They are never added together.',
            '',
            '**Overall: '.$result->overallStatus()->value.'.**'
                .($status['undetermined'] > 0 ? ' Some of this run could not be answered; see below before treating anything as clean.' : ''),
            '',
        ];
    }

    /**
     * The findings, blocking ones first, in a deterministic order.
     *
     * Ordered rather than sorted by cleverness: blocking before advisory, and within each group the
     * order the run produced. A report whose order changed between two identical runs would make
     * every diff of it unreadable.
     *
     * @param  list<array{0: Finding, 1: GateDecision}>  $decided
     * @return list<string>
     */
    private function findings(array $decided): array
    {
        // Ordered by the prioritizer rather than by collection order: an agent works top to bottom
        // and stops when it runs out of budget, so the sequence is what the format actually
        // delivers. The two lists below stay separated only to place the "nothing blocks" sentence
        // — the ORDER inside each is the prioritizer's, and blocking already sorts first in it.
        $ordered = $this->prioritizer->order($decided);

        $blocking = array_values(array_filter($ordered, static fn (array $pair): bool => $pair[1]->blockedBy instanceof GateAxis));
        $advisory = array_values(array_filter(
            $ordered,
            static fn (array $pair): bool => ! $pair[1]->blockedBy instanceof GateAxis && $pair[0]->status->outcome !== Outcome::Undetermined,
        ));

        $lines = ['## What to fix', ''];

        if ($blocking === [] && $advisory === []) {
            // Two different empties, and saying "no finding was reported" over the second would be a
            // small lie with a large consequence: a run that could not answer HAS reported
            // something, and the reader who stops at this section is the one it matters to.
            $unresolved = array_filter($decided, static fn (array $pair): bool => $pair[0]->status->outcome === Outcome::Undetermined);

            return [
                ...$lines,
                $unresolved === []
                    ? 'Nothing to fix: no finding was reported on this run.'
                    : 'Nothing to fix — but this run did not answer everything. Read the next section before concluding anything.',
                '',
            ];
        }

        if ($blocking === []) {
            $lines[] = 'Nothing blocks this change. The findings below are worth reading and do not stop a deploy.';
            $lines[] = '';
        }

        foreach ([...$blocking, ...$advisory] as [$finding, $decision]) {
            $lines = [...$lines, ...$this->finding($finding, $decision)];
        }

        return $lines;
    }

    /**
     * One finding, as much as an agent needs to act and no more.
     *
     * The documentation URL rather than the rule's whole explanation: a report that inlined every
     * rationale would be longer than the migrations it is about, and the reader who wants one can
     * follow a link. The downtime class is here because it is the field that changes what somebody
     * writes next.
     *
     * @return list<string>
     */
    private function finding(Finding $finding, GateDecision $decision): array
    {
        $axis = $decision->axis === GateAxis::Severity
            ? 'severity '.($finding->severity->value ?? 'unrated')
            : 'level '.$finding->level->value;

        $where = $finding->location->file ?? $finding->location->objectName ?? 'the run';

        return [
            '### '.$finding->ruleId.($decision->blockedBy instanceof GateAxis ? ' — BLOCKING' : ''),
            '',
            '- '.$finding->message,
            '- **Where:** '.$where.($finding->location->line !== null ? ':'.$finding->location->line : ''),
            '- **Judged by:** '.$axis
                .($finding->downtimeClass instanceof DowntimeClass ? ' · **Downtime:** '.$finding->downtimeClass->value : ''),
            '- **Why and how:** '.$finding->documentationUrl,
            // Three states and none of them silence: the sequence, a named absence, or the note
            // that SQLens built something and refused it. An empty gap here would make the second
            // and third indistinguishable from a finding nobody looked at.
            ...$this->remediation->render($finding),
        ];
    }

    /**
     * What the run could not answer — always present, never folded into the findings.
     *
     * Delegated to {@see UndeterminedSection}, which owns the explicit zero, the named reason per
     * entry and the next action per family. It is its own class because it is the section this
     * whole format exists to make unmissable, and a section rendered inline beside four others is
     * one a later edit can quietly shorten.
     *
     * @param  list<array{0: Finding, 1: GateDecision}>  $decided
     * @return list<string>
     */
    private function undetermined(array $decided): array
    {
        return $this->undeterminedSection->render(array_map(
            static fn (array $pair): Finding => $pair[0],
            $decided,
        ));
    }

    /**
     * What the agent reading this should not do.
     *
     * Short, and last, because it is the part somebody skims. It exists because a report that only
     * lists problems invites the reader to solve them, and the two failure modes worth naming are
     * both about acting past what the run actually established.
     *
     * @return list<string>
     */
    private function boundaries(): array
    {
        return [
            '## What not to do with this',
            '',
            '- **Do not treat an unanswered check as a pass.** Find out why it could not answer, or say',
            '  plainly that it did not.',
            '- **Do not change the schema beyond what a finding asks for.** A migration rewritten past',
            '  its finding is a change nobody reviewed.',
            '- **Check again rather than assuming.** Running the same command after an edit costs',
            '  seconds and is the only thing that shows the finding is gone.',
            '',
        ];
    }
}
