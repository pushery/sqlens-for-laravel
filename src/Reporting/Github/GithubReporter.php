<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Github;

use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\LocationKind;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\Severity;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The GitHub-annotations reporter: one workflow-command line per finding, so a
 * finding surfaces inline on the diff of a pull request instead of buried in a log.
 *
 * The annotation LEVEL comes from the axis that judges the finding, and only that
 * one. A security or privacy finding is weighed by its SEVERITY — `critical` and
 * `high` are errors, `medium` and `low` warnings, `info` a notice — so a critical
 * security finding is an error even when its rule sits at a low level, because
 * severity models risk rather than strictness appetite. Everything else is weighed
 * by its OUTCOME: a `fail` is an `::error`, a `pass` an `::notice`, an
 * `undetermined` a `::warning`.
 *
 * An `undetermined` on the severity axis is a `::notice`, deliberately, and it is
 * the one place the two axes disagree. The instinct is the opposite — a critical
 * risk nobody could rule out reads like a block — and this file carried that rule
 * for a while. It does not survive contact with a managed database, where the
 * application's role cannot read `pg_authid`, cannot read `pg_hba_file_rules` and
 * cannot see half of `mysql.*`: nearly every security check comes back
 * unanswerable, so every pull request would arrive permanently red. An annotation
 * weight buys attention, and attention that is always spent is attention nobody has
 * left. The block is not lost by this — `strict_undetermined` is what turns an
 * unanswerable check into a failing run, decided once per project. This mapping only
 * decides how loudly a diff says it, and it never drops the finding or its reason.
 *
 * Each line carries the finding's repo-relative file and, when it has one, its
 * line, so GitHub anchors the annotation to the exact spot. A finding WITHOUT a
 * source line does not silently fall to line 1: the message names why it has none
 * (a file-level migration finding, a live-schema object, a callsite without a
 * line), so the reader is never misled into looking at line 1. The message is the
 * rule id and the finding text, escaped per GitHub's workflow-command rules so a
 * newline or a `%` never corrupts the annotation or bleeds into the next one.
 *
 * GitHub displays at most ten annotations of each level per job. Rather than let
 * findings past that cap vanish, the reporter emits nine of an overflowing level
 * and then a single collector line — itself within the ten displayed — that names
 * how many were omitted and which rules, so the overflow is visible, never
 * swallowed. The full set always remains in the JSON report.
 *
 * An annotated run opens with a single `::notice::` preamble naming the run
 * parameters — mode, profile, the two gate thresholds, the server and tool versions
 * — so the reproducibility surface travels with the annotations, from the same
 * RunContext the console and JSON reporters read. It is a preamble to the
 * annotations, so a clean run emits neither it nor any annotation.
 *
 * Deterministic by construction: the findings are already deduplicated and stably
 * ordered by the Result, and the grouping and cap are order-preserving, so the same
 * state emits byte-identical annotations. A run with no findings emits nothing — an
 * empty annotation set is the honest "clean".
 */
final class GithubReporter implements Reporter
{
    /** GitHub displays at most this many annotations of each level per job. */
    private const int DISPLAY_LIMIT = 10;

    public function name(): string
    {
        return 'github';
    }

    public function report(Result $result, RunContext $context, OutputInterface $out): void
    {
        // The reproducibility preamble: a single ::notice:: naming the run parameters,
        // so an annotated PR carries the mode, profile, gates, and versions the result
        // came from, right above the annotations. It is a PREAMBLE to the annotations,
        // so a clean run — which emits no annotations — emits no preamble either: the
        // empty output stays the honest "clean", and the machine-facing JSON report is
        // where the parameters live unconditionally.
        if ($result->findings !== []) {
            $out->writeln($this->preamble($context));
        }

        // First pass: how many findings map to each command, so an overflowing level
        // can reserve a slot for its collector line inside the displayed budget.
        $counts = [];

        foreach ($result->findings as $finding) {
            $command = $this->command($finding);
            $counts[$command] = ($counts[$command] ?? 0) + 1;
        }

        // Second pass, in the Result's stable order: emit each finding until its
        // level's budget is spent, then route the rest to that level's overflow.
        $emitted = [];
        $overflow = [];

        foreach ($result->findings as $finding) {
            $command = $this->command($finding);
            $budget = $this->emitBudget($counts[$command] ?? 0);

            if (($emitted[$command] ?? 0) < $budget) {
                $out->writeln($this->annotation($command, $finding));
                $emitted[$command] = ($emitted[$command] ?? 0) + 1;

                continue;
            }

            $overflow[$command][] = $finding;
        }

        foreach ($overflow as $command => $findings) {
            $out->writeln($this->collectorLine($command, $findings));
        }
    }

    /**
     * The annotations to emit for a level that has `$count` findings: all of them
     * when they fit, otherwise one fewer than the display limit so the collector
     * line has a displayed slot of its own.
     */
    private function emitBudget(int $count): int
    {
        return $count > self::DISPLAY_LIMIT ? self::DISPLAY_LIMIT - 1 : $count;
    }

    /**
     * The workflow command a finding maps to — from the axis that judges it, and only that one.
     *
     * A pull request shows annotations as three visual weights and nothing else, so this mapping is
     * the entire severity signal a reviewer gets. Left on outcome alone, a critical security finding
     * and a level-9 pedantry note arrive as the same red line, and the reviewer's attention is spent
     * in the wrong place — which is the specific harm this ticket exists to prevent.
     *
     * For a severity-gated finding the weight therefore comes from the SEVERITY: `critical`/`high`
     * are errors, `medium`/`low` warnings, `info` a notice. A level finding keeps the outcome mapping
     * it already had, because the level gate is what decides whether it matters at all.
     */
    private function command(Finding $finding): string
    {
        if (GateAxis::forCategory($finding->category) === GateAxis::Severity && $finding->severity instanceof Severity) {
            // An undetermined keeps the weight of the risk it could not rule out, one step down: a
            // question nobody could answer is not the same as a finding, and it is not nothing
            // either. That is why it is a notice rather than being dropped.
            return $finding->status->outcome === Outcome::Undetermined
                ? 'notice'
                : $this->weightOf($finding->severity);
        }

        return match ($finding->status->outcome) {
            Outcome::Fail => 'error',
            Outcome::Pass => 'notice',
            // No severity escalation here, and its absence is the point.
            //
            // A finding reaches this branch when its category is NOT security or privacy. No RULE
            // outside those two carries a severity at all — pinned in GithubReporterTest, against
            // the shipped registry — so for rules an escalation would be unreachable code stating
            // the opposite of what this file decided twenty lines above.
            //
            // The DEPLOY family does carry one, and it still belongs on this path. A severity moves
            // an annotation because `security.min_severity` GATES on it; there is no
            // `deploy.min_severity`, and a preflight check runs whatever `--level` says. Its
            // severity ranks several failures against each other, and escalating by it would make an
            // `info` finding that FAILED look weaker than one that passed.
            Outcome::Undetermined => 'warning',
            // A check that had nothing to run against asks nobody to do anything, so it carries the
            // same weight as a pass — the weakest annotation there is. It is deliberately NOT
            // treated as an undetermined: an undetermined is a question left open, and escalating
            // "there was no question" to a warning would put a line in a reviewer's diff that no
            // change of theirs can ever remove.
            Outcome::NotApplicable => 'notice',
        };
    }

    /** The annotation weight a severity earns, in the one place the mapping is written. */
    private function weightOf(Severity $severity): string
    {
        return match ($severity) {
            Severity::Critical, Severity::High => 'error',
            Severity::Medium, Severity::Low => 'warning',
            Severity::Info => 'notice',
        };
    }

    /**
     * The run-parameter preamble as a single `::notice::` line. The same fields the
     * console header and the JSON `run` object carry, in the same order, read from the
     * one RunContext — so no reporter can disagree about the run a result came from.
     * The level and severity axes stay named separately, never merged.
     */
    private function preamble(RunContext $context): string
    {
        $run = $context->toArray();

        $parts = [
            'mode='.$run['mode'],
            'profile='.$run['profile'],
            'level<='.$run['level'],
            'min-severity='.($run['min_severity'] ?? 'off'),
            'strict-tools='.($run['strict_tools'] ? 'on' : 'off'),
            'strict-undetermined='.($run['strict_undetermined'] ? 'on' : 'off'),
            // Stated even when off: a pull request must not read a report that never
            // asked about down() as one that checked it.
            'roundtrip='.($run['roundtrip'] === true ? 'on' : 'off'),
        ];

        foreach ($run['server_versions'] as $server) {
            $parts[] = $server['connection'].'='.$server['version'].'/'.$server['source'];
        }

        foreach ($run['tool_versions'] as $name => $version) {
            $parts[] = $name.'='.$version;
        }

        return '::notice title=SQLens '.$this->escapeProperty($run['sqlens_version']).'::'
            .$this->escapeData('SQLens '.$run['sqlens_version'].' — '.implode(' ', $parts));
    }

    private function annotation(string $command, Finding $finding): string
    {
        $properties = $this->properties($finding);
        $prefix = $properties === '' ? '::'.$command.'::' : '::'.$command.' '.$properties.'::';

        return $prefix.$this->escapeData($finding->ruleId.': '.$finding->message.$this->confirmation($finding).$this->noLineNote($finding));
    }

    /**
     * Where a verdict was independently confirmed, in the MESSAGE rather than as its own
     * annotation.
     *
     * A second annotation for the same line would be the duplication this whole layer exists to
     * avoid — GitHub shows annotations against the diff, and two of them on one line reads as two
     * problems. Agreement is a property of the finding, not a finding.
     */
    private function confirmation(Finding $finding): string
    {
        return $finding->confirmedBy === [] ? '' : ' (confirmed by '.implode(', ', $finding->confirmedBy).')';
    }

    /**
     * The annotation title: the rule id, then the downtime class when the rule declared
     * one. GitHub renders it above the message and truncates long titles, so the ORDER
     * is load-bearing — the rule id comes first because it is what a reader needs to
     * look anything up, and it must survive a cut.
     *
     * The class is deliberately in the TITLE and not in the level: the annotation level
     * (`notice`/`warning`/`error`) is the severity axis, and downtime is a separate one.
     * A `blocking` change at a low level is still a low-level finding — mixing them
     * would make a deploy-impact note look like an escalation.
     */
    private function title(Finding $finding): string
    {
        // The axis, first thing in the title. A pull-request diff shows the title and little else,
        // and "why is this red in a level-2 run?" is the question a reader asks when the answer is
        // not in front of them. `[security/critical]` answers it before they open anything;
        // `[level 2]` says the other axis decided.
        $title = $this->axisPrefix($finding).' '.$finding->ruleId;

        if ($finding->downtimeClass instanceof DowntimeClass) {
            $title .= ' ('.$finding->downtimeClass->value.')';
        }

        return $title;
    }

    /**
     * `[security/high]` or `[level 2]` — the axis, and what it was measured against.
     *
     * The category rather than a literal "security": privacy is severity-gated too, and a prefix
     * that said `security` for a privacy finding would be a small lie repeated in every annotation.
     */
    private function axisPrefix(Finding $finding): string
    {
        if (GateAxis::forCategory($finding->category) === GateAxis::Severity) {
            return '['.$finding->category->value.'/'.($finding->severity instanceof Severity ? $finding->severity->value : 'unrated').']';
        }

        return '[level '.$finding->level->value.']';
    }

    /**
     * The collector line for a level's overflow: one annotation naming how many were
     * omitted and which rules, so the count past the cap is visible, not swallowed.
     *
     * @param  list<Finding>  $findings
     */
    private function collectorLine(string $command, array $findings): string
    {
        $ids = implode(', ', array_map(static fn (Finding $finding): string => $finding->ruleId, $findings));

        return '::'.$command.'::'.$this->escapeData(sprintf(
            '%d more %s finding(s) were not annotated (GitHub caps annotations at %d per level); see the full report. Omitted: %s',
            count($findings),
            $command,
            self::DISPLAY_LIMIT,
            $ids,
        ));
    }

    /**
     * The `title=…,file=…,line=…` property string, omitting each part the finding
     * lacks. The title is always present — every finding has a rule id — and comes
     * first, so a truncated title never loses it.
     */
    private function properties(Finding $finding): string
    {
        $properties = ['title='.$this->escapeProperty($this->title($finding))];

        if (is_string($finding->location->file) && $finding->location->file !== '') {
            $properties[] = 'file='.$this->escapeProperty($finding->location->file);
        }

        if (is_int($finding->location->line) && $finding->location->line > 0) {
            $properties[] = 'line='.$this->escapeProperty((string) $finding->location->line);
        }

        return implode(',', $properties);
    }

    /**
     * A named reason appended to the message when a finding has no source line, so
     * GitHub's fall-back to line 1 is never silent. Empty when the finding does have
     * a line — then the annotation anchors to it and needs no note.
     */
    private function noLineNote(Finding $finding): string
    {
        if (is_int($finding->location->line) && $finding->location->line > 0) {
            return '';
        }

        return ' (no source line: '.$this->noLineReason($finding->location->kind).')';
    }

    private function noLineReason(LocationKind $kind): string
    {
        return match ($kind) {
            LocationKind::Migration => 'anchored to the migration file, not a single statement',
            LocationKind::Catalog => 'a live-schema object, not a migration line',
            LocationKind::Callsite => 'a callsite without a resolved line',
        };
    }

    /** Escape a workflow-command MESSAGE: `%` first so later replacements are not re-escaped. */
    private function escapeData(string $value): string
    {
        return str_replace(['%', "\r", "\n"], ['%25', '%0D', '%0A'], $value);
    }

    /** Escape a workflow-command PROPERTY value: the message escapes plus `:` and `,`. */
    private function escapeProperty(string $value): string
    {
        return str_replace(['%', "\r", "\n", ':', ','], ['%25', '%0D', '%0A', '%3A', '%2C'], $value);
    }
}
