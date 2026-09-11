<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Console;

use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Contracts\Reporter;
use Pushery\SQLens\Deploy\DebtContext;
use Pushery\SQLens\Deploy\Escalation;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\StatisticsContext;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\Agent\RemediationRenderer;
use Pushery\SQLens\Reporting\EstimateNarrator;
use Pushery\SQLens\Reporting\ReportedInstance;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\Summary\AxisSummary;
use Pushery\SQLens\Reporting\Suppression\AuditIgnoreSuppressionSource;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\GateDecision;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Severity\SeverityGate;
use Pushery\SQLens\ShippedLocale;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The human-readable default output: a run rendered so pass, fail, and undetermined
 * are distinguishable at a glance, every undetermined shows its named reason, and
 * the two axes (level = strictness appetite, severity = risk) stay apart.
 *
 * Deterministic by construction — same input, same bytes, whatever the terminal:
 * no color codes, no terminal-width-dependent wrapping, no locale-formatted numbers.
 * That also satisfies NO_COLOR / --no-ansi trivially, because there is no color to
 * suppress. Findings arrive already ordered from the Result, so grouping by
 * file/subject is a single pass with no re-sorting.
 *
 * The stability marker is an English API token (like the rule id), never
 * translated: a preview or experimental rule is flagged so a reader in the terminal
 * — not only in the docs — knows the finding may still move. `stable` is unmarked so
 * the ordinary output stays quiet.
 *
 * The BALANCE is localized; the FINDING LINES are not. That line is deliberate:
 * the balance is prose a person reads, while a finding line carries the rule id,
 * the message prefix, the outcome value and the key=value pairs a machine and a
 * grep both depend on. Translating those would break every consumer and make the
 * console disagree with the JSON envelope about what a run found.
 */
final readonly class ConsoleReporter implements Reporter
{
    /**
     * @param  bool  $maintenanceWindowEnabled  the resolved `sqlens.reporting.maintenance_window`
     *                                          switch; on by default, and off is a deliberate
     *                                          choice a project makes rather than a fallback
     */
    public function __construct(
        private Translator $translator,
        private bool $maintenanceWindowEnabled = true,
        /**
         * Whether `--show-remediation` was passed.
         *
         * A constructor flag rather than a config key, and that is a deliberate avoidance: a new
         * key inside the nested `reporting` section would be missing from every consuming app that
         * has already published its config, and `mergeConfigFrom()` merges only the top level. This
         * is a per-RUN choice anyway — somebody at a terminal asking to see more, once — so config
         * would have been the wrong home even without that.
         */
        private bool $showRemediationSteps = false,
    ) {}

    /** The same reporter with the remediation sequence expanded — what `--show-remediation` returns. */
    public function showingRemediationSteps(): self
    {
        return new self($this->translator, $this->maintenanceWindowEnabled, true);
    }

    /** A balance label, from the package's own translation namespace. */
    private function label(string $key): string
    {
        return (string) $this->translator->get('sqlens::messages.reporting.'.$key, [], ShippedLocale::CODE);
    }

    /**
     * The denominator clause — ` — over 32 migrations` — or nothing when the run states no count.
     *
     * Every number on the summary line is a numerator, and a numerator alone cannot tell "nothing
     * was wrong" from "almost nothing was read". Measured in a consuming project:
     * `--path=database/migrations` reads one directory level, because that is what Laravel's own
     * `getMigrationFiles()` globs, so a tree of 32 central and 298 tenant migrations printed
     * `0 fail` and exited 0 over 32 files with nothing to say the other 298 existed.
     *
     * Omitted rather than printed as zero when the producer states no count: the audit reads a
     * catalog and has no file list, and `over 0 migrations` there would be a false statement rather
     * than a missing one.
     */
    private function denominator(RunContext $context): string
    {
        if ($context->subjectCount === null) {
            return '';
        }

        $noun = $this->label($context->subjectCount === 1 ? 'subject_singular' : 'subject_plural');

        return ' — '.$this->translator->get(
            'sqlens::messages.reporting.over_subjects',
            ['count' => (string) $context->subjectCount, 'noun' => $noun],
            ShippedLocale::CODE,
        );
    }

    public function name(): string
    {
        return 'console';
    }

    public function report(Result $result, RunContext $context, OutputInterface $out): void
    {
        $this->header($result, $context, $out);

        // The findings, split by the gate that judges them. Both sections keep the location
        // grouping inside them, because "which migration" is still the first thing a reader looks
        // for — the split is about which DIAL applies, not about reordering the work.
        $gate = new SeverityGate($context->minSeverity);
        $level = Level::from($context->level);

        // Keyed by the enum's VALUE: an enum case cannot be an array key in PHP, and spelling that
        // out here beats a lookup helper for two buckets.
        $sections = [GateAxis::Level->value => [], GateAxis::Severity->value => []];

        foreach ($result->findings as $finding) {
            $sections[GateDecision::for($finding, $level, $gate)->axis->value][] = $finding;
        }

        $this->axisSection($sections[GateAxis::Level->value], GateAxis::Level, $out);
        $this->axisSection($sections[GateAxis::Severity->value], GateAxis::Severity, $out);

        $this->suppressedSection($result, $out);

        $out->writeln('');
        $this->summary($result, $context, $out);
    }

    /**
     * One axis's findings under their own heading, or nothing at all when the axis is empty.
     *
     * ## Why two sections rather than one list with a column
     *
     * The two axes answer different questions, and a reader scanning one list has to hold both in
     * mind at once: "is this above my level?" and "is this above my risk floor?" — with the answer
     * depending on which category each line happens to be. Split, each section has ONE rule, and the
     * question a reader brings to it is the question it answers.
     *
     * It also makes the honest thing visible: a level-0 run can carry a full security section. That
     * looks wrong in a merged list ("why is this here, I asked for level 0?") and reads correctly
     * under its own heading.
     *
     * An empty axis prints nothing. A heading with no lines under it is a section a reader has to
     * scan to learn it is empty, and the summary already carries both counts.
     *
     * @param  list<Finding>  $findings
     */
    private function axisSection(array $findings, GateAxis $axis, OutputInterface $out): void
    {
        if ($findings === []) {
            return;
        }

        $out->writeln('');
        $out->writeln($this->label($axis === GateAxis::Severity ? 'security_findings' : 'level_findings'));

        $group = null;

        foreach ($findings as $finding) {
            $label = $this->groupLabel($finding->location);

            if ($label !== $group) {
                $out->writeln('');
                $out->writeln($label);
                $group = $label;
            }

            $out->writeln($this->line($finding, $axis));

            // Beneath the finding, never inside its line. The finding line is one row a reader scans
            // down a column; a strategy name spliced into it would push the location off the right
            // edge on the findings that have the most to say.
            foreach (new RemediationRenderer($this->translator)->consoleLines($finding, $this->showRemediationSteps) as $remediation) {
                $out->writeln($remediation);
            }
        }

        $this->stabilityLegend($findings, $out);
    }

    /**
     * What `[preview]` beside a rule id means, said once and only where one appeared.
     *
     * The marker has been on the finding line for some time with nothing anywhere explaining it. A
     * reader meeting `SEC.CFG.X [preview]` has to guess, and the two available guesses point
     * opposite ways: that the FINDING is provisional, or that the RULE is. It is the rule — the
     * finding is as real as any other, and acting on it is right.
     *
     * Conditional on a marker actually being present, which is the same rule this file keeps
     * everywhere else: a legend printed over a run that has nothing to explain is one more line a
     * reader learns to skip, and the habit does not stay confined to the harmless lines.
     *
     * @param  list<Finding>  $findings
     */
    private function stabilityLegend(array $findings, OutputInterface $out): void
    {
        $tiers = [];

        foreach ($findings as $finding) {
            if ($finding->stability !== StabilityTier::Stable) {
                $tiers[$finding->stability->value] = true;
            }
        }

        if ($tiers === []) {
            return;
        }

        $names = array_keys($tiers);
        sort($names, SORT_STRING);

        $out->writeln('');
        $out->writeln('  ['.implode('] / [', $names).'] marks the RULE, not the finding: the rule may still'
            .' change or be withdrawn, and this project opted into that tier. The finding itself is as'
            .' firm as any other.');
    }

    /**
     * Hidden findings are LISTED, not merely counted. Suppression takes a finding
     * out of the gate, not out of the report — a reader has to be able to see what
     * is being hidden and on whose say-so, or the balance is just a number to
     * trust.
     */
    private function suppressedSection(Result $result, OutputInterface $out): void
    {
        if ($result->suppressed === []) {
            return;
        }

        $out->writeln('');
        $out->writeln($this->label('suppressed_heading'));

        foreach ($result->suppressed as $hidden) {
            $parts = [
                '  ['.$hidden->suppression->source.']',
                $hidden->finding->ruleId,
                $this->groupLabel($hidden->finding->location),
                $this->label('reason').'='.$hidden->suppression->reason,
            ];

            if ($hidden->suppression->until !== null) {
                $parts[] = $this->label('until').'='.$hidden->suppression->until;
            }

            if ($hidden->suppression->undeterminedAllowed) {
                // Hiding a check that could not RUN is a stronger statement than
                // hiding a finding, so it never looks like an ordinary suppression.
                $parts[] = '('.$this->label('undetermined_allowed').')';
            }

            $out->writeln(implode('  ', $parts));
        }
    }

    private function header(Result $result, RunContext $context, OutputInterface $out): void
    {
        $out->writeln('sqlens '.$context->sqlensVersion.' — mode='.$context->mode->value.' profile='.$context->profile->value.' strict-tools='.$this->onOff($context->strictTools).' strict-undetermined='.$this->onOff($context->strictUndetermined));

        // The level gate's effect: the active level, and how many rules it admitted
        // versus hid — a hidden rule is a counted, visible choice, never a silent pass.
        $out->writeln('  level<='.$context->level.' active-rules='.$this->ruleCount($context->activeRuleCount).' hidden-rules='.$this->ruleCount($context->hiddenRuleCount).' evaluated-rules='.$this->evaluatedRules($context));

        // The severity axis, on its OWN line — the two gates (level = strictness
        // appetite, severity = risk) are orthogonal, so the header keeps them visibly
        // apart, never merged into one figure. "off" when the severity gate is not set.
        $out->writeln('  min-severity='.($context->minSeverity instanceof Severity ? $context->minSeverity->value : 'off'));

        // Whether the run replayed up → down → up. Stated even when off, and that is
        // the point: without it a reader cannot tell a report that CHECKED down() from
        // one that never asked, and silence would be read as "down() is fine".
        $out->writeln('  roundtrip='.$this->onOff($context->roundtrip));

        // The escape hatch, and the ONE header line that is conditional.
        //
        // Everything above is stated even when off, because "not asked" and "asked and negative"
        // are different answers and a reader cannot otherwise tell them apart. This field carries
        // that distinction in its own value instead: `null` means the producer has no gate to
        // waive at all — a lint run has no `--allow-undetermined` — and printing `off` there would
        // claim a fail-closed gate ran when none did.
        //
        // When a gate DID run, the line is unconditional, including `off`. That half matters more
        // than it looks: a deploy log has to be able to show that a green predeploy was earned
        // rather than waved through, and a line that appeared only on waivers would make its
        // absence the claim — which is the reading this package refuses everywhere else.
        if ($context->undeterminedWaiver !== null) {
            $out->writeln('  undetermined-waiver='.$this->onOff($context->undeterminedWaiver));
        }

        // The remediation contract, once and unconditionally. A run with no payload at all is
        // exactly the run where a reader most needs to know the tier exists — otherwise its absence
        // reads as "this build has no remediation" rather than "this run found nothing to
        // remediate", and those are different facts.
        $out->writeln('  remediation='.RemediationPayload::STABILITY->value
            .' (schema '.RemediationPayload::SCHEMA_VERSION.')');

        // The category axis: the categories this run was scoped to, or "all" when it
        // was not narrowed — a scoped run says so rather than looking like a full one.
        $out->writeln('  categories='.($context->activeCategories === [] ? 'all' : implode(',', $context->activeCategories)));

        // The maturity axis, unconditionally and even when it is only `stable`. A missing line
        // would read as "this build has no stability axis"; `stability=stable` is a statement.
        //
        // It is here for the run that finds NOTHING. A preview rule that reports is marked at its
        // own finding, so it is already visible; the one that stays silent is not, and two runs over
        // one unchanged tree — one admitting preview, one not — otherwise print identical headers
        // over different coverage.
        $out->writeln('  stability='.($context->admittedStability === [] ? 'none' : implode(',', $context->admittedStability)));

        // The external tools whose versions this run reasoned with — part of the
        // reproducibility surface, because the same migration can lint differently
        // against a different tool version. "none" when no tool was discovered.
        $tools = $context->toArray()['tool_versions'];
        $out->writeln('  tools='.($tools === [] ? 'none' : implode(', ', array_map(
            static fn (string $name, string $version): string => $name.' '.$version,
            array_keys($tools),
            $tools,
        ))));

        foreach ($context->toArray()['server_versions'] as $server) {
            $out->writeln('  connection '.$server['connection'].': '.$server['version'].' ('.$server['source'].')');
        }

        // WHICH instance the report is about, printed only when one was addressed — a lint run
        // over files has none, and an "instance: unknown" line there would invent a subject.
        if ($context->instance instanceof ReportedInstance) {
            $out->writeln('  instance '.$context->instance->describe());
        }

        // What could not be read, each with its reason, at the TOP. A run that skipped half the
        // catalog and one that found nothing to say produce the same clean summary, and only the
        // header can tell them apart before somebody acts on it.
        foreach ($context->sortedSkips() as $skip) {
            // The skip renders itself. Formatting it a second time here would put the same three
            // fields together in two places, and the two would drift the first time a field moved.
            $out->writeln('  skipped '.$skip->describe());
        }

        // Stated even at zero. "0 hidden" and a header that never mentions hiding read the same to
        // a person and mean different things to a pipeline.
        //
        // Broken down by the FORM that hid each one, when the audit ignore list is what did it. A
        // bare "12 suppressed" tells a reader that something is hidden; "9 by rule, 3 by object"
        // tells them how it got that way, and a rule silenced project-wide is a very different
        // state of a project from a single table silenced on purpose.
        // The scope of the claim, when there is one. A finding read without it is read as applying
        // to the whole system, and on a tenant database that is exactly the wrong conclusion.
        if ($context->tenant !== null) {
            $out->writeln('  tenant='.$context->tenant.' (this report describes that tenant only)');
        }

        $out->writeln('  suppressed='.count($result->suppressed).$this->ignoreBreakdown($result));
    }

    /**
     * ` (rules 9, objects 3)` — or an empty string when the audit ignore list hid nothing.
     *
     * Read off the reasons the source already wrote rather than counted separately: a second
     * tally beside them could disagree with the list it is supposed to describe.
     */
    private function ignoreBreakdown(Result $result): string
    {
        $counts = [];

        foreach ($result->suppressed as $hidden) {
            if ($hidden->suppression->source !== AuditIgnoreSuppressionSource::SOURCE) {
                continue;
            }

            if (preg_match('/\(([a-z]+)\)$/', $hidden->suppression->reason, $matches) === 1) {
                $counts[$matches[1]] = ($counts[$matches[1]] ?? 0) + 1;
            }
        }

        if ($counts === []) {
            return '';
        }

        // Sorted, so two runs over one state print one header.
        ksort($counts);

        return ' ('.implode(', ', array_map(
            static fn (string $form, int $count): string => $form.' '.$count,
            array_keys($counts),
            $counts,
        )).')';
    }

    /**
     * The maintenance-window advice, or null when the finding needs none or the project turned it
     * off.
     *
     * The switch exists because the advice is the same sentence every time — which is what makes
     * it trustworthy, and also what makes it noise for a team that has already internalized it.
     */
    private function maintenanceNote(Finding $finding): ?string
    {
        if (! $this->maintenanceWindowEnabled) {
            return null;
        }

        return $finding->maintenanceWindow()?->advice();
    }

    /**
     * What is actually wrong, in the words the rule wrote.
     *
     * ⚠️ THE CONSOLE REPORTER PRINTED NEITHER THIS NOR THE URL, AND IT IS THE DEFAULT FORMAT. The
     * dial line is assembled from `messagePrefix`, which is a SOURCE LABEL — the literal strings
     * `sqlens.lint`, `sqlens.audit`, `sqlens.security` — and not a sentence. So a real finding
     * reached the terminal as
     *
     *     [fail]  SEC.AUTH.HBA_TRUST_LOCAL  sqlens.lint  severity=medium  hba_rule
     *
     * A rule id, a label, and two dials: nothing saying what was found, and nothing saying where to
     * read about it. The message and the documentation URL are first-class fields on every finding
     * and this class read neither, so the sentence reached the JSON, SARIF and agent readers and
     * never the person at the terminal — the one reader who cannot go and look the id up in a
     * schema.
     *
     * The defect was already recorded HALF-WAY, a few lines below: the debt field is introduced by
     * a comment observing that these lines "carry the message PREFIX and never the message itself".
     * That threaded one value through for one rule family. This is the same observation applied
     * where it belongs.
     *
     * ⚠️ Do not name the two fields here in their `ClassName::$field` form. `ReporterLocalization`
     * scans this file as TEXT for a finding-building class that also reaches the translator, and it
     * cannot tell a docblock from a statement — the first draft of this comment failed that guard
     * over prose describing the fix.
     */
    private function messageNote(Finding $finding): ?string
    {
        // An empty message is a defect in the rule that built the finding, not something to paper
        // over with a blank line the reader has to interpret.
        return trim($finding->message) === '' ? null : $finding->message;
    }

    /**
     * Where to read about it — per finding, not once per run at the foot of the report.
     *
     * Every shipped promise about this address is a per-finding one ("every finding SQLens reports
     * can carry a link to the page that explains it"), a report is normally read by scrolling to
     * one finding rather than end to end, and the id-to-page mapping is precisely the thing a
     * reader cannot construct for themselves.
     */
    private function documentationNote(Finding $finding): ?string
    {
        return trim($finding->documentationUrl) === '' ? null : $finding->documentationUrl;
    }

    private function line(Finding $finding, GateAxis $axis): string
    {
        $parts = [
            '  ['.$finding->status->outcome->value.']',
            $finding->ruleId.$this->stabilityMarker($finding->stability),
            $finding->messagePrefix,
        ];

        // The dial that APPLIES, and only that one. A security finding carries a level in the
        // registry — the catalog is indexed by it — but the level gate never measures it, so
        // printing `level=0` beside it invites the reader to conclude a level-0 run would have
        // caught it. The same reasoning that removes the field from the JSON removes it here.
        if ($axis === GateAxis::Level) {
            $parts[] = 'level='.$finding->level->value;
        }

        if ($finding->severity instanceof Severity) {
            $parts[] = 'severity='.$finding->severity->value;
        }

        if ($finding->downtimeClass instanceof DowntimeClass) {
            $parts[] = 'downtime='.$finding->downtimeClass->value;
        }

        if ($finding->status->reason instanceof UndeterminedReason) {
            $parts[] = 'reason='.$finding->status->reason->value;
        }

        // What the ledger holds about this debt — and on this surface it is the ONLY way a reader
        // learns it. Measured while adding this: these lines carry the message PREFIX and never the
        // message itself, so the sentence `DebtNotices` builds ("open since 101 days") reaches the
        // JSON and SARIF readers and never the person at the terminal. Without this field they see
        // a rule id and a severity, and nothing at all about how long anything has been owed.
        //
        // Which is the whole question here. The safe two-step patterns are SUPPOSED to leave
        // something owed for a while; what separates a normal deploy from a forgotten one is how
        // long, and that number had no way to the terminal.
        //
        // Absent on every finding that is not a debt, and absent on the two notices that describe
        // the ACCOUNT rather than one debt — an unreadable ledger has no kind to print.
        if ($finding->debt instanceof DebtContext) {
            $parts[] = 'debt='.$finding->debt->kind.' '.$finding->debt->state->value.' '.(
                // An unreadable date says so and shows what it could not read, rather than printing
                // a `0d` that would report the oldest debt in the file as recorded this morning.
                $finding->debt->ageDays === null
                    ? 'age-unknown (first_seen='.$finding->debt->firstSeen.')'
                    : $finding->debt->ageDays.'d'
            );
        }

        // How big the objects this finding names are — context, never a verdict. It is printed with
        // the estimate marker attached rather than beside it, because the number and its worth are
        // one fact: a row count read off a catalog is always a guess, and a reader who sees `4.2M`
        // without `~` will act on it as though somebody counted.
        //
        // Absent for every run that read no statistics, which is what `lint` without a database
        // always is. That absence is not a small table; it is nobody having looked, and printing a
        // zero would be the invention this whole channel exists to avoid.
        if ($finding->statistics instanceof StatisticsContext) {
            // Narrated rather than `describe()`d. That method is the STABLE rendering — the one a
            // hash is taken over and two readings diff against — and translating it would give the
            // same database a different digest on a German machine. The person at the terminal gets
            // the other rendering, in their language, from the one class every user-facing estimate
            // goes through so a new output surface cannot forget the marker.
            $narrator = new EstimateNarrator($this->translator);

            $parts[] = 'size='.implode(', ', array_map(
                $narrator->narrate(...),
                $finding->statistics->estimates(),
            ));
        }

        // That the severity beside this line was RAISED, and by what. Without it the terminal shows
        // a critical finding and a size, and leaves the reader to work out whether the rule said
        // critical or a row estimate made it so — two different facts calling for two different
        // responses. The rule's verdict is about the migration; a raise is about this database
        // today, and it moves when somebody runs ANALYZE.
        if ($finding->escalation instanceof Escalation) {
            $parts[] = sprintf(
                'escalated=%s→%s (%s ≥ %s %s)',
                $finding->escalation->baseSeverity->value,
                $finding->escalation->escalatedSeverity->value,
                $finding->escalation->operation,
                number_format($finding->escalation->threshold),
                $finding->escalation->unit,
            );
        }

        // Where a verdict came from, when something outside SQLens agreed with it. The person at
        // the terminal has no other way to tell a finding two tools reached from one only we did,
        // and the difference is worth something: an independent agreement is a reason to trust a
        // verdict more, not a reason to print it twice.
        if ($finding->confirmedBy !== []) {
            $parts[] = 'confirmed-by='.implode(',', $finding->confirmedBy);
        }

        // A heuristic verdict says so on its own line, in the same words every time.
        // The machine reads `confidence` from the JSON; the person at the terminal
        // reads this — and reads it identically for every heuristic rule, because the
        // sentence comes from the enum rather than from whoever wrote the rule.
        if ($finding->confidence->isHeuristic()) {
            $parts[] = 'confidence='.$finding->confidence->value;
        }

        $parts[] = $this->locationDetail($finding->location);

        $line = implode('  ', $parts);

        // The extras are their OWN lines rather than another `key=value` on the summary line:
        // they are sentences a person reads, and squeezing a sentence into a field list is how a
        // line becomes something readers learn to skip.
        //
        // The order is the order a reader needs them in: what is wrong, then what that costs, then
        // where to read more. The message leads because it is the only one that is always present
        // and the only one that answers the first question anybody asks of a finding.
        foreach ([
            $this->messageNote($finding),
            $finding->confidence->honestyNote(),
            $this->maintenanceNote($finding),
            $this->documentationNote($finding),
        ] as $note) {
            if ($note !== null) {
                $line .= "\n      ".$note;
            }
        }

        return $line;
    }

    /** A preview/experimental rule carries a prefixed English marker; stable is unmarked. */
    private function stabilityMarker(StabilityTier $stability): string
    {
        return $stability === StabilityTier::Stable ? '' : ' ['.$stability->value.']';
    }

    private function summary(Result $result, RunContext $context, OutputInterface $out): void
    {
        $counts = $result->countsByStatus();

        $reasons = [];
        foreach ($result->countsByUndeterminedReason() as $reason => $count) {
            if ($count > 0) {
                $reasons[] = $reason.': '.$count;
            }
        }

        $undetermined = $counts[Outcome::Undetermined->value];
        $notApplicable = $counts[Outcome::NotApplicable->value];
        $reasonSuffix = $reasons === [] ? '' : ' ('.implode(', ', $reasons).')';

        // Shown only when there is one, and that is the opposite of the rule the JSON report
        // follows — deliberately. The machine-facing shape is stable so a consumer can index it
        // without asking whether the key exists; a human reading a clean PostgreSQL run should not
        // be told "0 not applicable" on every line, because a number that is always zero teaches a
        // reader to stop looking at it.
        $notApplicableSuffix = $notApplicable > 0
            ? ', '.$notApplicable.' '.$this->label('not_applicable')
            : '';

        // undetermined is reported on its OWN line item, never folded into "ok",
        // and so is suppressed: it is neither a pass nor a failure, it is a
        // decision somebody made. not-applicable sits BESIDE it rather than inside
        // it — "7 undetermined" and "7 undetermined, 4 not applicable" are two
        // different sentences about the same database.
        $out->writeln($this->label('summary').': '.$counts[Outcome::Fail->value].' '.$this->label('fail').', '.$undetermined.' '.$this->label('undetermined').$reasonSuffix.$notApplicableSuffix.', '.count($result->suppressed).' '.$this->label('suppressed').$this->denominator($context));

        if ($result->suppressed !== []) {
            $out->writeln($this->label('by_suppression_source').': '.$this->counts($result->countsBySuppressionSource()));
            // Per AXIS on its own line, beside per source. They answer different questions — who hid
            // it, and WHAT was hidden — and only the second notices a critical security finding
            // disappearing into a collective total: "12 suppressed by config" reads the same whether
            // the twelve are naming conventions or password literals.
            $out->writeln($this->label('by_suppressed_axis').': '.$this->counts($result->countsBySuppressedAxis()));
        }

        // A recorded suppression that matched nothing is its own silent green — the
        // list has stopped describing what the project accepts. Surfaced when present.
        if ($result->staleSuppressionCount() > 0) {
            $out->writeln($this->label('stale').': '.$result->staleSuppressionCount());
        }

        // The two gates are shown on SEPARATE lines with their thresholds, never a
        // merged total — a reader can see which gate a run breached, and that
        // security/privacy is gated by severity, not by the level.
        $axes = AxisSummary::for($result, $context);
        // The severity VALUE stays an API token; only the "gate is off" word is prose.
        $floor = $context->minSeverity instanceof Severity ? $context->minSeverity->value : $this->label('gate_off');
        $out->writeln($this->label('level_gate').' (<= '.$context->level.'): '.$axes->levelBreaches.' '.$this->label('breaching'));
        // The third number, beside the breach count and never folded into it: a breach is something
        // the run FOUND, an undetermined is something it could not look at. On a managed database
        // the second is often the larger, and a line showing only breaches would say "0 breaching"
        // about a run that answered almost nothing.
        $out->writeln(
            $this->label('severity_gate').' (>= '.$floor.'): '
            .$axes->severityBreaches.' '.$this->label('breaching')
            .', '.$axes->severityUndetermined.' '.$this->label('undetermined'),
        );

        $out->writeln($this->label('by_level').': '.$this->counts($result->countsByLevel()));
        $out->writeln($this->label('by_severity').': '.$this->counts($result->countsBySeverity()));
        // The third axis on its own line, next to the other two and never folded into
        // them: level is how strict the run was, severity is how risky a finding is,
        // and this is what deploying it does. The class NAMES stay English API tokens
        // in every locale — only the label in front of them is prose.
        $out->writeln($this->label('by_downtime').': '.$this->counts($result->countsByDowntimeClass()));
    }

    /** A stable, subject-scoped group label, derived from the location kind. */
    private function groupLabel(Location $location): string
    {
        return $location->file
            ?? $location->objectName
            ?? $location->driver
            ?? 'unknown';
    }

    private function locationDetail(Location $location): string
    {
        $bits = array_filter([
            $location->migrationClass,
            $location->statementIndex !== null ? 'stmt '.$location->statementIndex : null,
            $location->direction?->value,
            $location->line !== null ? 'line '.$location->line : null,
            $location->objectType?->value,
        ], static fn (?string $bit): bool => $bit !== null && $bit !== '');

        return $bits === [] ? '—' : implode(' ', $bits);
    }

    private function onOff(bool $value): string
    {
        return $value ? 'on' : 'off';
    }

    /**
     * How many rules were actually handed a subject, beside the count that were selected.
     *
     * A number rather than the list: the header is read at a glance, and forty rule ids would
     * bury the six lines around it. The identities are in the JSON envelope, where a consumer
     * comparing two runs needs them; here the job is to make the GAP visible — `active-rules=12
     * evaluated-rules=3` says nine checks did not happen, and no other line in this report says it.
     *
     * `n/a` rather than `0` when the producer does not report the set. Printing zero would state
     * that no rule ran, which is a real and alarming condition this must never be confused with.
     */
    private function evaluatedRules(RunContext $context): string
    {
        $evaluated = $context->sortedEvaluatedRuleIds();

        return $evaluated === null ? 'n/a' : (string) count($evaluated);
    }

    /**
     * A rule count, or `n/a` for a run that does not select rules at all.
     *
     * The same spelling {@see evaluatedRules()} above already uses, and for the same reason: `0`
     * and "this question does not arise" are two different answers, and a reader of
     * `sqlens:predeploy` -- which runs checks rather than rules -- got the first over seven
     * results with no way to tell.
     */
    private function ruleCount(?int $count): string
    {
        return $count === null ? 'n/a' : (string) $count;
    }

    /** @param  array<array-key, int>  $counts */
    private function counts(array $counts): string
    {
        $parts = [];
        foreach ($counts as $key => $count) {
            $parts[] = $key.'='.$count;
        }

        return implode(' ', $parts);
    }
}
