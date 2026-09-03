<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting;

use Pushery\SQLens\Capture\Shadow\GuardDecision;
use Pushery\SQLens\Deploy\Drift\DriftRunMode;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The immutable parameters of one SQLens run — the single source of the
 * reproducibility header every reporter prints and of a run's determinism claim.
 *
 * Determinism is a hard constraint on this VO: it carries NO timestamp, NO absolute
 * path, and NO hostname. A `generated_at` field would destroy every golden-file
 * check and every baseline, so "same state ⇒ same output" only holds because
 * nothing environment-varying lives here. Its array form has a fixed key order, and
 * the server and tool versions are emitted in a deterministic order regardless of
 * how they were collected.
 */
final readonly class RunContext
{
    /**
     * @param  list<ReportedServerVersion>  $serverVersions  one per addressed connection
     * @param  array<string, string>  $toolVersions  external tool name => version (empty until tool discovery lands)
     * @param  list<string>  $activeCategories  the categories this run was scoped to; empty means all
     * @param  list<string>  $admittedStability  the maturity tiers this run ADMITTED — what was allowed
     *                                           to run, never what reported
     * @param  list<ReportedSkip>  $skips  what could not be read, each with its named reason
     */
    public function __construct(
        public array $serverVersions,
        public array $toolVersions,
        public CaptureMode $mode,
        public RunProfile $profile,
        public bool $strictTools,
        public bool $strictUndetermined,
        public bool $roundtrip,
        public string $sqlensVersion,
        // The two orthogonal gate thresholds this run was configured with — the
        // strictness level (which rules ran) and the security-severity floor. They
        // are run parameters, so they belong in the reproducibility header. A null
        // min severity means the severity gate is not configured for this run.
        public int $level = 0,
        public ?Severity $minSeverity = null,
        // How many rules this run applied, and how many it did not — reported so a
        // withheld rule is a visible, counted choice and never a silent pass.
        //
        // Hidden means withheld for ANY reason: the level, the category scope, the
        // maturity tier, the server's version window. It used to mean "held back by
        // the level gate", which is one of the four, so a run narrowed by category
        // reported those rules as neither active nor hidden — and the audit suite
        // never filled the field at all, so every audit report said `hidden-rules=0`
        // whatever it had withheld. Both suites now answer registered-minus-active,
        // and `active + hidden == registered` is the invariant that keeps them from
        // drifting apart again. Why each rule is missing is not lost with it: the
        // version gate and the statistics axis each report their own named
        // undetermined finding.
        public int $activeRuleCount = 0,
        public int $hiddenRuleCount = 0,
        // The categories this run was narrowed to — the second, orthogonal filter
        // axis. Empty means "no filter": every category is active, exactly as an
        // empty `sqlens.categories` config means all. Reported so a run that was
        // scoped to one category shows it in the header rather than looking like a
        // full run that happened to find less.
        public array $activeCategories = [],
        public array $admittedStability = [],
        // WHICH instance this run is about, once one was addressed. Null for a run that
        // addresses none — a lint run over files has no instance, and printing a blank
        // one would invent a subject. Projected from the audit's own resolution rather
        // than resolved here: the reporting layer renders, it does not decide.
        public ?ReportedInstance $instance = null,
        // The areas the run could not read, each WITH its reason. In the header rather
        // than only in the findings, because the header is what gets read first and a
        // run that skipped half the catalog must not look complete at a glance.
        public array $skips = [],
        // WHICH tenant this report is about, when the project declared tenancy. Null for a
        // single-database project, which is the ordinary case and needs no qualifier.
        //
        // In the header rather than only in the config, because the scope of the claim is part of
        // the claim: a finding read without it is read as applying to the whole system, and on a
        // tenant database that is exactly the wrong conclusion.
        public ?string $tenant = null,
        /**
         * WHICH rules actually got a subject to judge — not how many were selected.
         *
         * `activeRuleCount` above is decided BEFORE anything is read: it counts the rules that
         * survived the level, category, maturity and version gates. It reads exactly the same
         * whether the catalog reading returned every table or none, so a run whose reader came back
         * empty reports the same "12 rules active" as one that judged all twelve — over a report in
         * which nothing was checked. That is the gap this list closes, and it is the reason the
         * count could not close it.
         *
         * A rule missing from here judged NOTHING, and its silence in the findings therefore means
         * "never asked" rather than "asked and found nothing". Those are the two readings a report
         * has to be able to tell apart; without this field they are one.
         *
         * **Null is not the empty list.** Null means this producer does not report the set at all —
         * the lint suite today. The empty list means a run that evaluated no rule, which is a real
         * and alarming state. Collapsing them would put "we do not measure this" and "nothing ran"
         * behind one value, which is the substitution the whole package is built to refuse.
         *
         * @var list<string>|null
         */
        public ?array $evaluatedRuleIds = null,
        /**
         * The session timeouts a preflight found IN FORCE, read back rather than requested.
         *
         * A set value is not an assurance; a read-back one is. Under transaction pooling a `SET`
         * is accepted, returns no error, and stops applying at the end of the transaction — so a
         * header printing what the run ASKED for would state a bound that does not hold, at the one
         * moment somebody is deciding whether to trust it.
         *
         * NULL for every producer that opens no session of its own, which is most of them — and
         * null rather than an empty map for the reason the field above spells out: "this producer
         * does not report the set" and "the set is empty" are different answers, and one value for
         * both is the substitution this package refuses everywhere.
         *
         * It also removes a shape flip a consumer would trip on. PHP serializes an empty map as
         * `[]` and a filled one as `{}`, so a field that could be either would change JSON TYPE
         * depending on its contents.
         *
         * @var array<string, int|null>|null
         */
        public ?array $sessionTimeouts = null,
        /**
         * How long each preflight check took, slowest first, as one line.
         *
         * In the header rather than only in a test's failure message, because the person who needs
         * it most is not running the test suite — they are watching a deploy take longer than they
         * expected and have no other way to see which question cost the time.
         *
         * Null for every producer that runs no checks.
         */
        public ?string $checkTimings = null,
        /**
         * What the whole run cost, in milliseconds — the SUM, where `checkTimings` is the split.
         *
         * Both, and not one of them, because they answer different questions. "Which question cost
         * the time" is read by a person, and a sentence is the right shape for that. "Did this run
         * take 4 s or 40 s" is read by a deploy script, and a sentence is the wrong shape entirely:
         * answering it from `check_timings` means parsing prose, which is what this package refuses
         * to make a consumer do everywhere else.
         *
         * The number was computed by both deploy commands from the day the budget existed and
         * reached nobody: it went into `RunMetadata`, which is projected by `Result::toArray()`,
         * which the JSON envelope does not emit and no shipped code calls at all. A
         * value that is measured and discarded is the same defect as a check that runs and says
         * nothing — and two source comments already told the reader this key was here.
         *
         * Null for every producer without a time budget, which is every lint and audit run. Null
         * rather than 0, because 0 ms is a claim about a run that happened.
         */
        public ?int $timeBudgetMsConsumed = null,
        /**
         * The production guard's verdict for a database-creating run — its inputs AND its outcome.
         *
         * Null for every run that never asked one, which is almost all of them: a pretend lint reads
         * files and creates nothing, so a guard block there would invent a decision nobody made.
         * Null rather than omitted, for the reason `instance` and `tenant` already state — a key
         * that disappears makes a consumer branch on its presence, and "this run needed no guard"
         * then looks the same as "an older SQLens wrote this report".
         *
         * Why it belongs in the reproducibility header rather than only in the findings: a blocked
         * run reports every subject as `shadow_guard_blocked`, which says THAT the guard held it and
         * not WHICH check did. The three are not interchangeable — a disallowed environment is a
         * configuration decision, a production connection is a target mistake, and a missing
         * confirmation is a one-flag fix — and without this a reader has to guess between them. The
         * environment and the force flag travel with it for the same reason `strict_tools` and
         * `roundtrip` do: a run nobody can explain afterwards is not a reproducible one.
         */
        public ?GuardDecision $guard = null,

        /**
         * Whether `--allow-undetermined` actually waived a block on this run.
         *
         * Three-valued, like everything else this package reports, and each value is a different
         * statement:
         *
         * - `null` — this producer has no gate to waive. A lint run has no such flag, so the
         *   question does not apply, and answering `false` would claim a fail-closed gate ran.
         * - `false` — a gate ran and nothing was waived. The verdict is the checks' own.
         * - `true` — the run was blocked ONLY by checks that could not answer, the escape hatch was
         *   open, and the exit code is clean because somebody asked for it to be.
         *
         * It is in the reproducibility header because that last case is the one a deploy log has to
         * be able to show. Without it a waived run and a genuinely clean run produce the same exit
         * code, the same green tick and the same report — and "the gate passed" then means two
         * different things that nobody can tell apart afterwards. That is precisely the silent
         * green this gate exists to refuse, moved one level up into the record of the run.
         *
         * Null rather than omitted, for the reason `instance`, `tenant` and `guard` already state.
         */
        public ?bool $undeterminedWaiver = null,

        /**
         * Which POLICY a drift run applied — report or gate — or null on a producer that has none.
         *
         * Separate from `mode` above and not a rename of it: that one says HOW the expectation side
         * was built (`shadow` — a real replay into a throwaway database), which is a statement about
         * method. This one says whether the run was allowed to block, which is a statement about
         * consequence. A reader needs both and they answer different questions.
         *
         * Without it, a `report` run and a `gate` run over the SAME drifted database produce
         * byte-identical documents. The exit codes differ — clean against findings-above-gate — but
         * the exit code is not what gets archived; the document is. A pipeline reading yesterday's
         * report cannot then tell a green run that found nothing from a green run that was never
         * allowed to say so, which is the silent green this command's own console output already
         * refuses by printing the mode beside the findings.
         *
         * Null rather than omitted, for the reason `instance`, `tenant`, `guard` and
         * `undetermined_waiver` already state.
         */
        public ?DriftRunMode $driftMode = null,

        /**
         * The schema object types this run COMPARED — the scope, in the document that gets archived.
         *
         * A drift report says which objects differ. It could not say which KINDS of object were ever
         * looked at, and the two readers do not look at the same ones: measured at nine types on
         * PostgreSQL, six on MySQL, and no routine on either. So a report reading `"entries": []`
         * meant "no drift among whatever this build happens to compare" while looking exactly like
         * "no drift", and the consumer with no way to tell the difference is the machine one — an
         * agent or a deploy script, which is precisely who reads this field.
         *
         * Sorted `value` strings rather than the enum, because this is the serialized surface and a
         * reader outside PHP has no enum. Null rather than omitted, for the reason `instance`,
         * `tenant`, `guard`, `undetermined_waiver` and `drift_mode` already state.
         *
         * @var list<string>|null
         */
        public ?array $comparedObjectTypes = null,

        /**
         * Whether this run PROVED the schema matches its migrations, and by what — the expectation
         * comparison as its own block rather than mixed into the findings.
         *
         * Three states, and the third is why the field exists at all. `sqlens:postdeploy` compares
         * only when `--expect-shadow` asks it to, so a report with no drift findings can mean "they
         * agree" or "nobody looked", and those are opposite statements. The console run says which
         * on stderr; the DOCUMENT is what a pipeline archives, and until this field it said neither.
         *
         * A shape rather than a bool, because "not compared" carries a reason worth keeping: a
         * driver with no shadow support, a guard that declined a production connection, a migration
         * set that could not be enumerated. Null rather than omitted, for the reason `instance`,
         * `tenant`, `guard`, `undetermined_waiver` and `drift_mode` already state — here it means
         * the producing command has no expectation stage at all.
         *
         * @var array{requested: bool, compared: bool, note: string}|null
         */
        public ?array $expectation = null,

        /**
         * The active RUNTIME GUARD profile, or the literal string `off`.
         *
         * Not to be confused with `guard` one field over, which is the PRODUCTION guard's verdict on
         * a shadow provision. The two share a word and nothing else, which is why this one is
         * emitted as `guard_profile`.
         *
         * NEVER omitted, and that is the whole reason it is a string rather than a nullable name: a
         * deactivated guard that does not appear in the output reads exactly like an active one. A
         * reader scanning a header for `guard` and finding nothing concludes the field is not
         * emitted by this version, not that the guardrails are off.
         *
         * Null here means the PRODUCER has no guard stage at all — the same meaning `instance`,
         * `tenant`, `guard` and `drift_mode` give their nulls — and every command that boots the
         * package has one, so in practice it is always a name or `off`.
         */
        public ?string $guardProfile = null,
    ) {}

    /**
     * The same context, with the drift policy filled in.
     *
     * Derived rather than passed at construction for the same reason the waiver is: the context is
     * assembled from configuration before the command resolves its own flags, and the mode is a
     * decision that `--fail-on-drift` and `deploy.drift.mode` make together.
     */
    public function withDriftMode(DriftRunMode $driftMode): self
    {
        return $this->copyWith(
            undeterminedWaiver: $this->undeterminedWaiver,
            driftMode: $driftMode,
            comparedObjectTypes: $this->comparedObjectTypes,
            expectation: $this->expectation,
            guardProfile: $this->guardProfile,
        );
    }

    /**
     * The same context, with the compared scope filled in.
     *
     * Derived like the two above, and for a sharper reason: the scope is a property of the READER,
     * which the command resolves after the context is assembled — a driver is chosen from the
     * connection, and until then nobody knows whether nine types or six are on the table.
     *
     * Sorted here rather than at the call site so two runs against one database produce one document.
     *
     * @param  non-empty-list<SchemaObjectType>  $types
     */
    public function withComparedObjectTypes(array $types): self
    {
        $values = array_map(static fn (SchemaObjectType $type): string => $type->value, $types);
        sort($values);

        return $this->copyWith(
            undeterminedWaiver: $this->undeterminedWaiver,
            driftMode: $this->driftMode,
            comparedObjectTypes: $values,
            expectation: $this->expectation,
            guardProfile: $this->guardProfile,
        );
    }

    /**
     * The same context, with the waiver decision filled in.
     *
     * The commands learn whether the hatch actually opened only after the checks have run, while
     * the context is built before them — so this derives rather than mutates. Written out field by
     * field because the class is `final readonly`: there is no clone-with in this language version,
     * and a reflection-driven copy would silently keep working while dropping a field somebody adds
     * later.
     */
    public function withUndeterminedWaiver(bool $waived): self
    {
        return $this->copyWith(
            undeterminedWaiver: $waived,
            driftMode: $this->driftMode,
            comparedObjectTypes: $this->comparedObjectTypes,
            expectation: $this->expectation,
            guardProfile: $this->guardProfile,
        );
    }

    /**
     * The same context, with the expectation comparison on the record — including "it did not run".
     *
     * Derived like the three above and for the same reason: whether the schema was compared against
     * its migrations is a flag the command resolves, and the context is assembled from configuration
     * before any flag is read.
     *
     * @param  array{requested: bool, compared: bool, note: string}  $expectation
     */
    public function withExpectation(array $expectation): self
    {
        return $this->copyWith(
            undeterminedWaiver: $this->undeterminedWaiver,
            driftMode: $this->driftMode,
            comparedObjectTypes: $this->comparedObjectTypes,
            expectation: $expectation,
            guardProfile: $this->guardProfile,
        );
    }

    /**
     * The ONE hand-written field list, so a second derivation cannot drop a field the first keeps.
     *
     * There used to be exactly one `with…` method and therefore exactly one copy. A second arrived
     * with the drift policy, and two copies of twenty-two arguments is two places for a new field to
     * be forgotten — while `UndeterminedWaiverIsOnTheRecordTest` only ever compares one of them.
     *
     * @param  list<string>|null  $comparedObjectTypes
     * @param  array{requested: bool, compared: bool, note: string}|null  $expectation
     */
    private function copyWith(?bool $undeterminedWaiver, ?DriftRunMode $driftMode, ?array $comparedObjectTypes, ?array $expectation, ?string $guardProfile): self
    {
        return new self(
            serverVersions: $this->serverVersions,
            toolVersions: $this->toolVersions,
            mode: $this->mode,
            profile: $this->profile,
            strictTools: $this->strictTools,
            strictUndetermined: $this->strictUndetermined,
            roundtrip: $this->roundtrip,
            sqlensVersion: $this->sqlensVersion,
            level: $this->level,
            minSeverity: $this->minSeverity,
            activeRuleCount: $this->activeRuleCount,
            hiddenRuleCount: $this->hiddenRuleCount,
            activeCategories: $this->activeCategories,
            admittedStability: $this->admittedStability,
            instance: $this->instance,
            skips: $this->skips,
            tenant: $this->tenant,
            evaluatedRuleIds: $this->evaluatedRuleIds,
            sessionTimeouts: $this->sessionTimeouts,
            checkTimings: $this->checkTimings,
            timeBudgetMsConsumed: $this->timeBudgetMsConsumed,
            guard: $this->guard,
            undeterminedWaiver: $undeterminedWaiver,
            driftMode: $driftMode,
            comparedObjectTypes: $comparedObjectTypes,
            expectation: $expectation,
        );
    }

    /**
     * The skips in a stable order — the one both reporters print.
     *
     * Sorted here rather than trusted from the caller: the catalog reader records skips in whatever
     * order it met the objects, which is a property of the moment and not of the state. Two runs
     * over one state must produce one header, byte for byte, or every golden report in this
     * repository becomes a coin toss.
     *
     * @return list<ReportedSkip>
     */
    public function sortedSkips(): array
    {
        $skips = $this->skips;
        usort($skips, static fn (ReportedSkip $a, ReportedSkip $b): int => $a->sortKey() <=> $b->sortKey());

        return $skips;
    }

    /**
     * The evaluated rule ids in a stable order, or null when this producer does not report them.
     *
     * Sorted and de-duplicated here rather than trusted from the caller, for the same reason the
     * skips are: a runner records them in the order it happened to meet subjects, which is a
     * property of the moment and not of the state. A rule that judged forty tables appears once.
     *
     * @return list<string>|null
     */
    public function sortedEvaluatedRuleIds(): ?array
    {
        if ($this->evaluatedRuleIds === null) {
            return null;
        }

        $ids = array_values(array_unique($this->evaluatedRuleIds));
        sort($ids, SORT_STRING);

        return $ids;
    }

    /**
     * The reproducibility header as a fixed-key-order array for the JSON reporter.
     * Server versions are sorted by connection name and tool versions by tool name,
     * so the same run always serializes byte-identically.
     *
     * @return array{
     *     sqlens_version: string,
     *     mode: string,
     *     profile: string,
     *     level: int,
     *     active_rules: int,
     *     hidden_rules: int,
     *     evaluated_rules: list<string>|null,
     *     session_timeouts: array<string, int|null>|null,
     *     check_timings: string|null,
     *     time_budget_ms_consumed: int|null,
     *     active_categories: list<string>,
     *     admitted_stability: list<string>,
     *     min_severity: string|null,
     *     strict_tools: bool,
     *     strict_undetermined: bool,
     *     roundtrip: bool,
     *     server_versions: list<array{connection: string, version: string, source: string}>,
     *     tool_versions: array<string, string>,
     *     instance: array{connection: string, driver: string, host: string|null, port: int|null, database: string|null, role: string, role_reason: string|null, pin_verdict: string|null, pooler: string|null}|null,
     *     skips: list<array{area: string, reason: string, detail: string|null}>,
     *     tenant: string|null,
     *     guard: array{mode: string, environment: string, force: bool, guard: string}|null,
     * }
     *
     * Note what is NOT here: the suppressed count. It belongs in the header a reader sees, but the
     * authority for it is the RESULT, and a copy on this object could be set to a different number
     * with nothing to notice — a header saying "0 hidden" over a report that hid forty. Each
     * reporter reads it from the result it is already holding, so there is one source and no
     * opportunity to disagree.
     */
    public function toArray(): array
    {
        $servers = $this->serverVersions;
        usort($servers, fn (ReportedServerVersion $a, ReportedServerVersion $b): int => $a->connection <=> $b->connection);

        $tools = $this->toolVersions;
        ksort($tools);

        $skips = $this->sortedSkips();

        return [
            'sqlens_version' => $this->sqlensVersion,
            'mode' => $this->mode->value,
            'profile' => $this->profile->value,
            'level' => $this->level,
            'active_rules' => $this->activeRuleCount,
            'hidden_rules' => $this->hiddenRuleCount,
            // Null rather than omitted, like `instance` and `tenant`: a key that disappears makes a
            // consumer branch on its presence, and "this producer does not report the set" then
            // looks the same as "an older SQLens wrote this report". The empty list is a different
            // answer again — a run that evaluated nothing.
            'evaluated_rules' => $this->sortedEvaluatedRuleIds(),
            // What the session REPORTED, never what it asked for. Empty for a producer that opens
            // no session of its own, which is absence rather than a claim that nothing is bounded.
            'session_timeouts' => $this->sessionTimeouts,
            'check_timings' => $this->checkTimings,
            'active_categories' => $this->activeCategories,
            'min_severity' => $this->minSeverity?->value,
            'strict_tools' => $this->strictTools,
            'strict_undetermined' => $this->strictUndetermined,
            // Stated even when off, like `min_severity` and `tool_versions`: without
            // it a reader cannot tell a report that CHECKED down() from one that
            // never asked. Silence would be read as "down() is fine", which is
            // exactly the reading this package refuses — and a per-migration
            // undetermined on every ordinary run would be worse, escalating every
            // strict run that did not opt in.
            'roundtrip' => $this->roundtrip,
            'server_versions' => array_map(
                fn (ReportedServerVersion $version): array => $version->toArray(),
                $servers,
            ),
            'tool_versions' => $tools,
            // Nullable rather than omitted: a key that disappears makes a consumer branch
            // on its presence, and "the run had no instance" then looks identical to "an
            // older SQLens wrote this report".
            'instance' => $this->instance?->toArray(),
            'skips' => array_map(
                static fn (ReportedSkip $skip): array => $skip->toArray(),
                $skips,
            ),
            // Null rather than omitted, like the instance: a key that disappears makes a consumer
            // branch on its presence, and "this project has one database" then looks the same as
            // "an older SQLens wrote this report".
            'tenant' => $this->tenant,
            // The guard's own rendering, not a second one. `GuardDecision` has always described
            // this array as "the run-header parameters"; until this key existed, nothing read it.
            'guard' => $this->guard?->toArray(),
            // The one key a deploy script can gate on. `true` here is the difference between "the
            // database was checked and is fine" and "the checks could not answer and somebody
            // waved it through" — two states that otherwise share an exit code, a green tick and a
            // report. Null means this producer has no gate at all, which is a third answer again.
            'undetermined_waiver' => $this->undeterminedWaiver,
            'drift_mode' => $this->driftMode?->value,
            'compared_object_types' => $this->comparedObjectTypes,
            'expectation' => $this->expectation,
            // `guard_profile`, NOT `guard`: the header already carries a `guard` field, and it is
            // the production guard's verdict on a shadow provision. Two unrelated facts under one
            // key is a consumer reading one and acting on the other.
            'guard_profile' => $this->guardProfile,
            // The remediation payload's own contract, stated ONCE for the run.
            //
            // Every payload already carries these two beside itself, and that is the right place to
            // answer "what am I holding" for a payload in hand. It is the wrong place to answer the
            // question a consumer asks FIRST: should I touch this field at all? That decision is
            // made before parsing four hundred findings, by whoever wires the integration — and
            // until now the only way to reach the answer was to find a finding that happened to
            // carry a payload. A run whose findings all lack one said nothing about the tier, which
            // reads as "no such contract" rather than "nothing to show you".
            'remediation_contract' => [
                'schema_version' => RemediationPayload::SCHEMA_VERSION,
                'stability' => RemediationPayload::STABILITY->value,
            ],
            // Which maturity tiers this run ADMITTED — `["stable"]` on an unconfigured project,
            // because empty means stable-only on this axis rather than "all" the way it does for
            // categories. Named as a list rather than as a flag, so opting into two tiers reads as
            // two tiers.
            //
            // In the header for the run that finds NOTHING. A preview rule that reports marks itself
            // at the finding; the one that stays silent is invisible, and two runs over one unchanged
            // tree — one admitting preview, one not — otherwise produce identical headers over
            // different coverage.
            'admitted_stability' => $this->admittedStability,
            // The sum beside the split, as a number rather than inside a sentence: `check_timings`
            // answers "which question cost the time" for a person, this answers "did this run take
            // 4 s or 40 s" for a deploy script, and reading the second off the first means parsing
            // prose. Last rather than next to its sibling because the key order follows the version
            // registers, and this field belongs to version 5 (see JsonEnvelope).
            //
            // Null on a producer with no time budget — not 0, which is a claim about a run that ran.
            'time_budget_ms_consumed' => $this->timeBudgetMsConsumed,
        ];
    }
}
