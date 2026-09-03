<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Json;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\Summary\AxisSummary;
use Pushery\SQLens\Reporting\Suppression\SuppressedFinding;
use Pushery\SQLens\Severity\GateAxis;
use Pushery\SQLens\Severity\GateDecision;
use Pushery\SQLens\Severity\SeverityGate;

/**
 * The versioned JSON envelope every machine consumer reads — CI evaluation, the
 * report-diff command, and the agent layer. Its shape is deliberate and stable:
 *
 * - `schema_version` is public API from 1.0 on. Renaming or removing a field bumps
 *   it, and so does ADDING one: without a bump, a consumer that does not see
 *   `confidence` cannot tell whether this run had nothing to say about confidence or
 *   whether the producer predates the field. Those are different answers and a
 *   contract that cannot distinguish them is not stable, only unchanged.
 * - `run` is the reproducibility header, straight from RunContext — one source, so
 *   the console and JSON headers can never drift.
 * - `summary` keeps the level and severity axes in SEPARATE count maps, plus the
 *   three-valued status counts and the undetermined-reason breakdown.
 *
 *   The reason breakdown is an OPEN enumeration and its growth does not bump the
 *   version, which is the one deliberate exception to the rule above. It is not an
 *   inconsistency: the map always carries EVERY reason this build knows, zeros
 *   included, so a consumer reading it learns the producer's whole vocabulary from
 *   the payload itself — the ambiguity a bump exists to resolve cannot arise. Naming
 *   a newly distinguished failure is also not a contract change; it is the taxonomy
 *   getting more honest, and versioning it would make the number churn until it
 *   stopped meaning anything. REMOVING or renaming a reason key is a different
 *   matter, and does bump.
 * - `findings` reuses each Finding's own deterministic projection, and `suppressed`
 *   lists every hidden finding WHOLE, with the source and reason that hid it.
 *   Suppression removes a finding from the gate, never from the record: a hidden
 *   finding a consumer cannot see or explain is indistinguishable from one that
 *   never happened.
 *
 * There is no timestamp and no absolute path anywhere in it — both would destroy
 * diffability and reproducibility. The key order is fixed, so the same input
 * serializes byte-identically.
 */
final readonly class JsonEnvelope
{
    /**
     * The envelope schema version. It lives HERE and nowhere else: four separate
     * changes add a field to this report, and if each bumped the version itself the
     * published number would depend on the order they merged in — and every other
     * change's pin test would be red until it rebased. One version, one source.
     */
    public const int SCHEMA_VERSION = 5;

    /**
     * The RUN-level fields version 4 introduces.
     *
     * Kept apart from the per-finding registers below because they answer to different guards: a
     * per-finding field is checked against what a finding actually emits, and a run field against
     * the header's fixed key order. Merging them into one list would let a run field pass the
     * finding guard by being absent from every finding, which is exactly what it is.
     *
     * It shipped for one day with NO guard at all — the sentence above described a check that did
     * not exist, and `grep` found this declaration and no reader. That is the shape this package
     * refuses in rules, so it does not get an exemption in the register that announces a schema
     * bump. `tests/Feature/Reporting/JsonReporterTest.php` now holds it in both directions.
     *
     * @var list<string>
     */
    public const array RUN_FIELDS_ADDED_IN_V4 = [
        'evaluated_rules',
        // What a preflight session reported IN FORCE. Declared here for the same reason
        // `evaluated_rules` is: a run field that appears without being announced is the silent
        // contract change the version register exists to prevent.
        'session_timeouts',
        // How long each check took, slowest first. In the header rather than only in a test's
        // failure message, because the person who needs it most is watching a deploy take longer
        // than expected and has no other way to see which question cost the time.
        'check_timings',
        // The production guard's verdict, for a run that asked one. It rides version 4 rather than
        // bumping to 5 for the reason `statistics` states below: it lands in the same unreleased
        // cycle, and one version per cycle is what the note on SCHEMA_VERSION asks for.
        //
        // Null for every run that created nothing, which is almost all of them. A consumer must not
        // read that null as "the guard allowed it" — it means no guard was ever asked.
        'guard',
    ];

    /**
     * The run fields version 5 introduces.
     *
     * Its own register rather than an appendix to the one above, and the distinction is not
     * bookkeeping: `RUN_FIELDS_ADDED_IN_V4` is a claim about which schema a consumer needs in order
     * to see those keys. Quietly adding a field to it would tell a reader on version 4 that they
     * already had this one, which is exactly the silent contract change the registers exist to
     * prevent.
     *
     * @var list<string>
     */
    public const array RUN_FIELDS_ADDED_IN_V5 = [
        // Whether `--allow-undetermined`, or the project setting behind it, turned a blocked deploy
        // gate into a clean exit. Three-valued: null where the producer has no gate at all, false
        // where one ran fail-closed, true where it was waived.
        //
        // In the header rather than only in the exit code, because those two are otherwise
        // indistinguishable: a waived green and an earned one share a code, a tick and a report,
        // and "predeploy passed" then means two different things nobody can separate afterwards.
        'undetermined_waiver',

        // Which policy a drift run applied — `report` or `gate` — null on a producer that has none.
        //
        // Announced here rather than added quietly for the reason the register above states: a run
        // field that appears without being declared is the silent contract change these lists exist
        // to prevent. It joins version 5 rather than opening a sixth because version 5 has not
        // shipped — no consumer holds it yet, so nobody is being told they already had this key.
        'drift_mode',

        // Which kinds of schema object the run COMPARED — null on a producer that compares none.
        //
        // The field a `"entries": []` needs in order to mean anything. Two readers do not cover the
        // same ground (nine types on PostgreSQL, six on MySQL, no routine on either), so an empty
        // finding list was "nothing differs among whatever this build happens to look at" while
        // reading exactly like "nothing differs". A human gets the same sentence on stderr; this is
        // the half an agent or a deploy script can act on.
        //
        // Joins version 5 for the reason `drift_mode` states: version 5 has not shipped, so nobody
        // is being told they already had this key.
        'compared_object_types',

        // Whether the run PROVED the schema matches its migrations, and if not, why not.
        //
        // The one field that separates two opposite statements a report otherwise makes with the
        // same silence. `sqlens:postdeploy` compares only when `--expect-shadow` asks it to, so a
        // document with no `DEPLOY.DRIFT.*` finding means either "the migrations and the database
        // agree" or "nobody looked" — and a deploy dashboard reading the first where the second is
        // true is the silent green this package refuses. The person at the console is told on
        // stderr; this is the half that survives being archived.
        //
        // Three-valued like the two above: null on a producer with no expectation stage at all,
        // `{requested: false}` where the option was not passed, `{compared: false}` with a named
        // reason where it was and could not run.
        //
        // Joins version 5 for the reason `drift_mode` states: version 5 has not shipped, so nobody
        // is being told they already had this key.
        'expectation',

        // The active RUNTIME GUARD profile, or the literal string `off`.
        //
        // Never omitted, and that is why it is a string rather than a nullable name: a deactivated
        // guard that does not appear in the header reads exactly like an active one, and a consumer
        // scanning for it and finding nothing concludes the field is not emitted by this version
        // rather than that the guardrails are off.
        //
        // `guard_profile` and not `guard`, because `guard` is already taken by the PRODUCTION
        // guard's verdict on a shadow provision. The two share a word and nothing else, and two
        // unrelated facts under one key is a consumer reading one and acting on the other.
        //
        // Joins version 5 for the reason `drift_mode` states: version 5 has not shipped.
        'guard_profile',

        // The remediation payload's schema version and stability tier, once for the run.
        //
        // Per payload they were already there. What was missing is the answer to the question a
        // consumer asks before parsing anything: is this field settled enough to build on? A run
        // whose findings all lack a payload previously said nothing at all about the tier, which
        // reads as "no such contract" rather than "nothing to show you".
        'remediation_contract',

        // Which maturity tiers the run admitted. Announced rather than added quietly, for the reason
        // this register exists — and it joins version 5 rather than opening a sixth because version 5
        // has not shipped: the package carries no release tag at all, so no consumer holds any
        // version of this envelope and nobody is being told they already had this key.
        //
        // It answers the question the finding-level `stability` marker cannot: that marker is on a
        // finding, so it only ever describes a rule that FOUND something. A run that admitted preview
        // and found nothing looked exactly like a run that never admitted it.
        'admitted_stability',

        // What the whole run cost, in milliseconds — the SUM beside `check_timings`, which is the
        // split and is a SENTENCE. A deploy script asking "did this take 4 s or 40 s" had to parse
        // prose to find out, which is the shape this package refuses everywhere else.
        //
        // It is not a new measurement: both deploy commands have computed it since the budget
        // existed, and it went into `RunMetadata` — projected by `Result::toArray()`, which this
        // envelope does not emit and which no shipped code calls at all. Two source comments told
        // the reader `run.time_budget_ms_consumed` was already here.
        //
        // ⚠️ It reads as if it belonged beside `check_timings`, and in the HEADER it cannot: these
        // registers are concatenated in order to pin the header's key order, so a field declared in
        // version 5 has to appear after every version-4 field. Putting it where it reads best would
        // tell a consumer on version 4 that they already had it, which is the silent contract change
        // these lists exist to prevent.
        //
        // Wall-clock, so it differs on every run: named in `McpCliParity` beside `check_timings`,
        // which was always excluded for the same reason.
        //
        // Null for every producer without a budget, which is every lint and audit run — and null
        // rather than 0, because 0 ms is a claim about a run that happened.
        'time_budget_ms_consumed',
    ];

    /**
     * The per-finding fields version 5 introduces: the ledger's account of a debt, on the finding
     * that reports it.
     *
     * A debt has always BEEN a finding here — the notice builders use the same factories every rule
     * uses. What it could not do was say so in a form a machine reads: the kind, the age and the
     * state reached a consumer only as English prose inside `message`, so getting the age off a
     * finding meant parsing the sentence "open since 94 days".
     *
     * Present only on a finding that reports one specific recorded debt. Absent on every other
     * finding, and absent on the two notices that describe the ACCOUNT rather than a debt — an
     * unreadable ledger has no `debt_kind`, and inventing one out of the fact that nothing could be
     * read is exactly the silent green this package refuses.
     *
     * `age_days` is absent when `first_seen` would not parse, or when the run did not age it at all
     * (the repository side holds no reference date). `first_seen` is always there when the rest of
     * this group is, so the pair is what names the absence: a reader who finds the date and no age
     * is looking straight at the reason.
     *
     * `debt_kind` also appears one level down, inside `remediation` — a different question ("this
     * fix would OPEN a debt of that kind") drawing on the same vocabulary. They must never disagree,
     * which is why both copy the registrar's word rather than spelling it themselves.
     *
     * @var list<string>
     */
    public const array FIELDS_ADDED_IN_V5 = [
        'debt_kind',
        'first_seen',
        'age_days',
        'debt_state',
    ];

    /**
     * The per-finding fields version 4 introduces.
     *
     * `statistics` is the deploy suite's context channel: how big the objects a finding names are,
     * each number carrying whether it was measured or estimated. It rides version 4 rather than
     * bumping to 5 because it lands in the same unreleased cycle as the run field above — one
     * version per cycle, which is what the note on SCHEMA_VERSION asks for.
     *
     * It is OPTIONAL in the strongest sense: `lint` without a database emits findings with no
     * statistics at all, and that is not a degraded run. A consumer must not read the field's
     * absence as "the objects are small" — absence means nobody looked.
     *
     * The same holds for the escalation keys beside it, one degree more strongly: they are present
     * only on a finding a raise actually happened to, so their absence is the COMMON case and says
     * nothing at all — not that the object was small, and not that nobody looked.
     *
     * @var list<string>
     */
    public const array FIELDS_ADDED_IN_V4 = [
        'statistics',
        // The five the escalation adds, and they travel with `statistics` rather than in a version
        // of their own because they are the same fact stated twice: the numbers, and what the
        // numbers did to the severity. A consumer that reads one without the other cannot tell an
        // escalated `high` from a rule that rated it `high` by itself.
        'escalated',
        'base_severity',
        'escalated_severity',
        'operation',
        'threshold',
    ];

    /**
     * The per-finding fields version 2 introduces, declared rather than smuggled.
     *
     * The register is not documentation: {@see JsonEnvelope}
     * is held to it by a test that compares the keys a finding actually emits against
     * this list plus the version-1 base. A field added later without being declared
     * here fails the build — which is the whole point, because an undeclared additive
     * field is exactly the silent contract change the version exists to announce.
     *
     * `downtime_class` and `stability` already ship; `confidence` and
     * `maintenance_window` arrive with their own changes and touch nothing here.
     *
     * @var list<string>
     */
    public const array FIELDS_ADDED_IN_V3 = [
        'blocked_by',
        // Present only when a payload existed and was REFUSED — never for a rule that produced
        // none. Declared rather than shipped quietly for the reason the register exists at all: a
        // field a consumer cannot see coming is a contract change wearing an unchanged version.
        'remediation_refusal',
    ];

    /**
     * The per-finding fields version 2 added.
     *
     * @var list<string>
     */
    public const array FIELDS_ADDED_IN_V2 = [
        // Declared late, and placed by MEASUREMENT rather than by convenience: it began shipping in
        // a change that touched `Finding::toArray()` and not this file, while the version here was
        // still 2 — so a version-2 document could already carry it, and version 2 is where it
        // belongs. Backfilling it to the current version would tell a consumer it arrived later
        // than it did.
        //
        // Why nothing noticed for eleven days is the part worth keeping. The register guards compare
        // EMITTED against DECLARED, which is the right direction — but this key is filtered away
        // unless something confirmed the finding, and no fixture built one. The guard was blind at
        // its extractor rather than at its rule, so a completeness arm now holds every declared
        // field to being reachable by at least one fixture.
        'confirmed_by',
        'confidence',
        'downtime_class',
        'maintenance_window',
        'stability',
    ];

    /**
     * The per-finding fields version 1 shipped.
     *
     * @var list<string>
     */
    public const array FIELDS_IN_V1 = [
        'category',
        'context',
        'documentation_url',
        'level',
        'location',
        'message',
        'message_prefix',
        'remediation',
        'rule_id',
        'severity',
        'status',
        'undetermined_reason',
    ];

    private function __construct(
        private Result $result,
        private RunContext $context,
    ) {}

    public static function for(Result $result, RunContext $context): self
    {
        return new self($result, $context);
    }

    /**
     * One finding, with the two GATE facts a consumer cannot derive from the finding alone.
     *
     * ## Why the gate decides these and not the finding
     *
     * A finding is a fact about a migration; whether it blocks is a judgment about a RUN. The same
     * finding blocks or does not depending on the level and the floor this run chose, so those
     * fields belong to the reporter that has the run context — not to the value object, which would
     * have to be handed the gates to answer.
     *
     * `blocked_by` is read from `GateDecision` rather than recomputed here. That is the whole point
     * of that object: the exit code, the summary counts and this field are three readers of one
     * decision, and three readers computing it separately is how a report starts disagreeing with
     * the exit code it was printed beside.
     *
     * `level` is NULLED for a severity-gated finding, and that is a correction rather than a
     * cosmetic. A security finding carries a level in the registry — it has to, the catalog is
     * indexed by it — but the level gate never measures it. Serializing `level: 0` invites a
     * consumer to conclude that a level-0 run would have caught it and a level-4 run would too,
     * both of which miss that the level is not the axis in play at all.
     *
     * @return array<string, mixed>
     */
    private function finding(Finding $finding): array
    {
        $decision = GateDecision::for(
            $finding,
            Level::from($this->context->level),
            new SeverityGate($this->context->minSeverity),
        );

        $projection = [
            ...$finding->toArray(),
            'level' => $decision->axis === GateAxis::Severity ? null : $finding->level->value,
            'blocked_by' => $decision->blockedBy?->value,
        ];

        // Through the same null filter the finding's own projection uses. One rule for the whole
        // document: a field that has no value is ABSENT, never present-as-null. Two conventions in
        // one object would make a consumer ask which fields are optional in which sense — and the
        // schema version is what says whether a field exists at all, so absence needs no second
        // spelling.
        return array_filter($projection, static fn (mixed $value): bool => $value !== null);
    }

    /**
     * @return array{
     *     schema_version: int,
     *     run: array<string, mixed>,
     *     summary: array{overall_status: string, counts: array<string, array<array-key, int>>, level_gate: array{threshold: int, breaching: int}, severity_gate: array{threshold: string|null, breaching: int}, suppressed: int, stale: int},
     *     findings: list<array<string, mixed>>,
     *     suppressed: list<array<string, mixed>>,
     * }
     */
    public function toArray(): array
    {
        return [
            'schema_version' => self::SCHEMA_VERSION,
            'run' => [
                ...$this->context->toArray(),
                // Read from the RESULT, which is the authority, rather than carried on the run
                // context beside it: two copies of one number is one copy too many for a number
                // whose whole job is to stop "clean" and "clean once forty findings were hidden"
                // from looking alike.
                'suppressed' => count($this->result->suppressed),
            ],
            'summary' => [
                'overall_status' => $this->result->overallStatus()->value,
                'counts' => [
                    'status' => $this->result->countsByStatus(),
                    'level' => $this->result->countsByLevel(),
                    'severity' => $this->result->countsBySeverity(),
                    // So a deploy script can decide from the head of the report,
                    // without walking every finding: "did anything in this release
                    // block or rewrite?"
                    'downtime_class' => $this->result->countsByDowntimeClass(),
                    'category' => $this->result->countsByCategory(),
                    'undetermined_reason' => $this->result->countsByUndeterminedReason(),
                    // Per source, so "12 suppressed" can always be traced to who
                    // suppressed them — a count without an author is not a balance.
                    'suppressed_by_source' => $this->result->countsBySuppressionSource(),
                    // Per AXIS beside per source, because they answer different questions: who hid
                    // it, and what was hidden. Only the second notices a critical security finding
                    // disappearing into a collective total.
                    'suppressed_by_axis' => $this->result->countsBySuppressedAxis(),
                ],
                'suppressed' => count($this->result->suppressed),
                // The one field a deploy script reads to decide whether this release needs a
                // window. It is an AGGREGATE of the histogram above rather than a fourth count,
                // and it is here rather than derived by the consumer because deriving it means
                // knowing the order of the three classes — this package's judgment, not theirs,
                // and not alphabetical.
                //
                // Null when no finding carries a class at all. That is not `online`: most findings
                // have no class, because the class is a property of a schema OPERATION and a
                // security finding is not one.
                'worst_downtime_class' => $this->result->worstDowntimeClass()?->value,
                // Recorded suppressions that matched nothing this run — a rotting
                // suppression list is surfaced, never left silent.
                'stale' => $this->result->staleSuppressionCount(),
                // The two gates as SEPARATE objects, each with its threshold and its
                // breach count — never a merged total that hides which gate broke.
                ...AxisSummary::for($this->result, $this->context)->toArray(),
            ],
            'findings' => array_map(
                $this->finding(...),
                $this->result->findings,
            ),
            'suppressed' => array_map(
                static fn (SuppressedFinding $hidden): array => $hidden->toArray(),
                $this->result->suppressed,
            ),
        ];
    }
}
