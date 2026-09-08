<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\Connection as DatabaseConnection;
use Illuminate\Filesystem\Filesystem;
use Pushery\SQLens\Canonical\Extensions\CanonicalExtensionRegistry;
use Pushery\SQLens\Canonical\Fingerprint;
use Pushery\SQLens\Catalog\CatalogReaderFactory;
use Pushery\SQLens\Catalog\CatalogRequest;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Catalog\Objects\GrantReading;
use Pushery\SQLens\Catalog\Objects\HbaReading;
use Pushery\SQLens\Catalog\Objects\RlsReading;
use Pushery\SQLens\Catalog\Objects\RoleReading;
use Pushery\SQLens\Catalog\Objects\RoutineReading;
use Pushery\SQLens\Catalog\PoolerReading;
use Pushery\SQLens\Catalog\ReaderConnectionFactory;
use Pushery\SQLens\Catalog\Security\ConnectionSeparation;
use Pushery\SQLens\Catalog\Security\SecuritySubjects;
use Pushery\SQLens\Catalog\SettingCrossFacts;
use Pushery\SQLens\Catalog\SettingsReading;
use Pushery\SQLens\Catalog\SettingSubjects;
use Pushery\SQLens\Catalog\Usage\IndexUsageProjection;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Categories\CategoryFilter;
use Pushery\SQLens\Categories\CategorySelection;
use Pushery\SQLens\Config\ConfigViolation;
use Pushery\SQLens\Config\RuleIdReference;
use Pushery\SQLens\Config\RuleIdValidator;
use Pushery\SQLens\Console\ExitCode;
use Pushery\SQLens\Console\ExitCodeResolver;
use Pushery\SQLens\Contracts\Driver;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Contracts\SecurityReader;
use Pushery\SQLens\Deploy\DebtCollector;
use Pushery\SQLens\Deploy\DebtLedger;
use Pushery\SQLens\Deploy\DebtLedgerRefusal;
use Pushery\SQLens\Deploy\DebtMode;
use Pushery\SQLens\Deploy\DebtNotices;
use Pushery\SQLens\Deploy\DebtOrigin;
use Pushery\SQLens\Deploy\DebtReconciliation;
use Pushery\SQLens\Deploy\DebtRegistrar;
use Pushery\SQLens\Deploy\DebtThresholds;
use Pushery\SQLens\Deploy\PostdeployContext;
use Pushery\SQLens\Deploy\PostdeployVerifier;
use Pushery\SQLens\Drivers\DriverRegistry;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\EngineIdentity;
use Pushery\SQLens\Drivers\ServerVersionFloor;
use Pushery\SQLens\Exceptions\UnreadableBaseline;
use Pushery\SQLens\Findings\CredentialRedactor;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\RunMetadata;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Levels\LevelGate;
use Pushery\SQLens\PackageVersion;
use Pushery\SQLens\Reporting\Baseline\BaselineFile;
use Pushery\SQLens\Reporting\Baseline\BaselineRuleIds;
use Pushery\SQLens\Reporting\Baseline\ConfiguredBaseline;
use Pushery\SQLens\Reporting\Baseline\FindingFingerprint;
use Pushery\SQLens\Reporting\Baseline\StaleBaselinePolicy;
use Pushery\SQLens\Reporting\CaptureMode as ReportingCaptureMode;
use Pushery\SQLens\Reporting\ConfigRunContextCollector;
use Pushery\SQLens\Reporting\ReportedInstance;
use Pushery\SQLens\Reporting\ReportedServerVersion;
use Pushery\SQLens\Reporting\ReportedSkip;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Reporting\RunProfile;
use Pushery\SQLens\Reporting\Suppression\SuppressionCandidate;
use Pushery\SQLens\Reporting\Suppression\SuppressionResolver;
use Pushery\SQLens\Reporting\VersionSource;
use Pushery\SQLens\Rules\AuditVersionGate;
use Pushery\SQLens\Rules\RuleRegistry;
use Pushery\SQLens\Rules\ServerVersion;
use Pushery\SQLens\Rules\StabilityGate;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Security\Privacy\PrivacyPack;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;
use Pushery\SQLens\Tools\MissingToolNotice;
use Pushery\SQLens\Tools\Squawk\SquawkRuleIds;
use Pushery\SQLens\Tools\ToolContributions;
use Pushery\SQLens\Tools\ToolDiagnostic;
use Pushery\SQLens\Tools\ToolLocator;
use Pushery\SQLens\Tools\UnverifiableToolPrefixes;
use Throwable;

/**
 * The audit run: one catalog reading, one set of subjects, every active rule over them.
 *
 * ## One reading, shared
 *
 * The snapshot is read ONCE and every rule judges the same objects. That is not an optimization —
 * it is what makes a report internally consistent. Two readings of a live database are two
 * different databases, and rules that disagreed about what they saw would produce a report whose
 * findings cannot all be true at the same time. It is also the only way `primum non nocere` can
 * hold: one connection, one session, one set of bounded queries, whatever the rule count.
 *
 * ## Nothing here reads
 *
 * The runner consumes a snapshot; it issues no SQL and knows no engine. The driver branch lives in
 * {@see CatalogReaderFactory}, which is also where the session's read-only seal is chosen. So the
 * worst this class can do to a database is nothing at all.
 *
 * ## Silence is never a pass
 *
 * Two ways a run can look clean while having checked nothing, and both are answered:
 *
 * - **No rule survived the filters.** A level and category combination that admits nothing is
 *   reported as a named undetermined, because "nothing was checked" and "everything checked out"
 *   are the same output otherwise.
 * - **The reading was incomplete.** Every skip the catalog reader recorded travels into the result
 *   with its reason, so an audit of a database that half-refused to be read says so.
 */
final readonly class AuditRunner implements AuditRuns
{
    /**
     * How long the debt pass may take, as an `hrtime(true)` span.
     *
     * Its own bound rather than a share of the audit's, because it runs a different kind of reading
     * on a connection the audit has already finished with — and an unbounded catalog pass on a
     * production server is the harm the whole session design exists to prevent.
     */
    private const int DEBT_BUDGET_NS = 10_000_000_000;

    public function __construct(
        private InstanceResolver $instances,
        private CatalogReaderFactory $readers,
        private ReaderConnectionFactory $connections,
        private DriverRegistry $drivers,
        private ExitCodeResolver $exitCodes,
        private Repository $config,
        private ProjectManifest $manifest,
        /**
         * The external tools this run may lean on.
         *
         * The audit route had none until a tool arrived that reads a live CATALOG rather than a
         * file — every amplifier before it judged migrations, which is the lint route's business.
         * Nothing here names a tool: what a run reports about an absence, and which suppressions
         * it refuses to call stale, are both asked of the diagnostic.
         */
        private PostdeployVerifier $debtChecks,
        private ToolLocator $tools,
        /**
         * What each amplifier ADDS, resolved by contract rather than by name.
         *
         * Separate from the locator because the two answer different questions: the locator says
         * whether a tool is there, this says whether anything can act on it. A tool is worth
         * reporting as missing long before that second answer is yes.
         */
        private ToolContributions $contributions,
        /**
         * The canonicalization used to give a debt ONE identity, whichever side found it.
         *
         * Needed here since the catalog side can register a debt, because a reference
         * canonicalized differently from the migration side's would be the duplicate the registrar
         * exists to prevent. Taking the same registry the lint route takes is what makes "one
         * canonicalization path" true rather than intended.
         */
        private CanonicalExtensionRegistry $extensions,
    ) {}

    public function run(
        ?string $connection = null,
        ?string $host = null,
        ?int $level = null,
        ?array $categories = null,
        ?bool $strictUndetermined = null,
        bool $ignoreBaseline = false,
        ?bool $strictTools = null,
        DebtMode $debt = DebtMode::Check,
    ): AuditOutcome {
        // Bundled at the door and threaded as ONE value from here on. Two adjacent nullable
        // booleans passed by hand through a dozen private helpers is a shape where forgetting one
        // at one site compiles and produces a run that ignores the flag it was given.
        $overrides = new RunOverrides($strictUndetermined, $strictTools);
        // FIRST, so every header this method can produce — including the refusals below, which never
        // reach a rule — states the scope the operator asked for. The audit used to resolve this
        // deep inside the rule filter and never report it at all, which made a run narrowed to one
        // category indistinguishable from an unnarrowed one in the only place a reader looks.
        $scope = CategorySelection::forRun($categories, $this->config->get('sqlens.categories'));
        $selectedCategories = $scope->categories;
        $activeCategories = $scope->values();

        // BEFORE anything connects. A typo in an ignore list must not surface after twenty seconds
        // of catalog reading, and it must not surface as a rule that quietly kept firing while the
        // project believed it was off — which is what an unvalidated id does, for months, because
        // a pattern matching nothing looks exactly like a pattern whose findings are gone.
        $misconfigured = [...$this->ignoreListViolations(), ...$this->baselineViolations($ignoreBaseline)];

        if ($misconfigured !== []) {
            return $this->refusedConfig($misconfigured, $level, $overrides, $activeCategories);
        }

        // Also before anything connects, and for the same reason: there is no safe default tenant to
        // fall back on. Every tenant is the wrong one to pick on a project's behalf, so the run
        // stops rather than producing a report about one customer that reads like a report about
        // the application.
        $tenancy = $this->tenancyRefusal($level, $overrides, $activeCategories);

        if ($tenancy instanceof AuditOutcome) {
            return $tenancy;
        }

        $resolution = $this->instances->resolve($connection, $host);
        $target = $resolution->target;

        if (! $target instanceof InstanceTarget) {
            return $this->refused($resolution, $level, $overrides, $activeCategories);
        }

        $activeLevel = $level ?? $this->configuredLevel();
        $context = $this->subjectContext($target, $overrides);

        // Held rather than resolved twice: the readers are built twice below, and each call would
        // otherwise open its own connection to the same instance — two sessions where the whole
        // design is one.
        $session = $this->connections->forConnection($target->connection, $target->pinnedHost);

        // The connection forced open HERE, deliberately, before anything else touches it.
        //
        // Laravel connects lazily, so without this the first PDO attempt happens somewhere inside a
        // reader — and a failure there arrives as an uncaught QueryException that ends the command:
        // exit code 1 (which this package defines as "findings breached a gate"), a zero-byte
        // `--output` file that reads as a clean report, and the connection's coordinates written to
        // the console and the host application's error log.
        //
        // Opening it at one named point makes the failure mean exactly one thing. Later failures
        // are a different question — a reader losing a privilege mid-run is a catalog degradation,
        // and the translator already answers that one — so this catch stays around the connect and
        // nothing else, rather than becoming a blanket that would swallow real defects too.
        try {
            $session->getPdo();
        } catch (Throwable $error) {
            return $this->unreachable($target, $context, $error, $activeLevel, $overrides, $activeCategories);
        }

        $readers = $this->readers->for($target->driver, $session, $this->connections->budget(), $context);

        // The identity FIRST, and the catalog second. Which instance answered is part of what the
        // report asserts, so a run that read a schema and then failed to say whose it was would
        // have produced findings nobody can act on.
        // BEFORE the identity read, and before anything opens a transaction: transaction pooling is
        // only observable outside one, and the catalog session works exclusively inside one.
        $pooler = $readers->pooler?->read()
            ?? PoolerReading::undetermined(['this driver has no pooler probe']);

        $identity = $readers->identity->read($target->connection);
        $target = $target->withIdentity($identity)->withPooler($pooler);

        // Re-stamped now that the instance has answered. The readers were handed a context BEFORE
        // this — they need one to be constructed at all — so the role could not have been on it
        // then, and a context built once would have put `undetermined` on every finding of a run
        // that knew perfectly well which machine it was talking to. Caught by a test asserting the
        // role on the findings rather than in the header, which is the only place the two shapes
        // of this bug look different.
        $context = $context->withInstanceRole($target->role()->value);

        // …and the readers are rebuilt around it. They carry the context INTO the findings they
        // make themselves — a catalog skip is the reader's finding, not the runner's — so leaving
        // them on the pre-identity context produced a report where some findings knew the role and
        // some did not. That is worse than none knowing it: a reader comparing two findings would
        // reasonably conclude they came from different instances.
        $readers = $this->readers->for($target->driver, $session, $this->connections->budget(), $context);

        // The pin verified against the SERVER, before a single catalog row is read. A pin that did
        // not take effect means every finding below would be about a database nobody asked for —
        // and it would be indistinguishable from a real report, so the run stops here rather than
        // producing one. Checked before the catalog read on purpose: reading a server the operator
        // did not choose is itself the harm, not merely a reporting mistake.
        if ($target->pinVerdict() === PinVerdict::Divergent) {
            return $this->refusedPin($target, $context, $activeLevel, $overrides, $activeCategories);
        }

        // The engine, checked AFTER the pin verdict and before a single catalog row is read.
        // After, because a divergent pin means the server that answered is not the one the
        // operator addressed — an engine verdict about a machine nobody asked for is advice
        // about the wrong server, and the pin refusal is the more specific complaint.
        //
        // MariaDB answers Laravel's `mysql` driver without sharing MySQL 8.4 semantics, so
        // every rule below this line would judge it against a contract it never made. The
        // banner comes from the identity read that already happened — this opens nothing.
        $engineDriver = $this->drivers->resolve($target->driver);

        // Only when the instance actually NAMED a version. `check()` answers
        // `unverifiedEngineIdentity` for a null banner, and turning that into a refusal here would
        // reject a perfectly ordinary MySQL whose version reading degraded — while the run already
        // names that gap through the identity reader. Found by the wiring proof, which refused a
        // healthy instance on its first run; the same trap the floor unit was rebuilt to make
        // unmakeable, arriving through the caller instead of the unit.
        $banner = $target->identity?->serverVersion;

        $engine = $engineDriver instanceof Driver && is_string($banner) && $banner !== ''
            ? new EngineIdentity()->check($engineDriver, $banner)
            : null;

        if ($engine instanceof DriverResolutionFailure) {
            return $this->refusedEngine($engine, $target, $context, $activeLevel, $overrides, $activeCategories);
        }

        $snapshot = $readers->catalog->read($this->request());

        // Read BESIDE the catalog, through the contract's own accessor, and joined onto the tables
        // here. Deliberately not part of the snapshot: usage counters move while the schema stands
        // still, and folding them in would cost the snapshot the determinism the drift comparison
        // depends on. Deliberately not read by the rule either — a rule that queried the statistics
        // views itself would be a second code path into the same data, free to disagree with this
        // one about scope, privileges and degradation.
        $snapshot = new CatalogSnapshot(
            $snapshot->context,
            IndexUsageProjection::attachTo($snapshot->objects, $readers->catalog->indexUsage($this->request())),
            $snapshot->skips,
        );

        // The server's own configuration, read over the SAME session and turned into subjects the
        // rule engine already dispatches. Without this the server-baseline rules are registered,
        // level-gated and reported in the registry — and never handed a subject, so they would
        // answer nothing on every real run while their unit tests stayed green. A rule the pipeline
        // cannot reach is a rule that does not exist, however complete it looks from the inside.
        $settings = $readers->settings->read();

        // Measured beside the settings, never instead of them. A driver that collects nothing hands
        // back an empty set, and a rule that needed a fact from it then reports `undetermined` —
        // which is why the absence is an explicit empty rather than a skipped call.
        $crossFacts = $readers->crossFacts?->collect() ?? SettingCrossFacts::none();

        // The security state, on the same terms: read over the same session, turned into subjects the
        // same dispatcher already walks. A driver without a security reader hands back nothing, and a
        // security rule then has no subject to judge — which is a state the rule reports, not one it
        // silently passes.
        $roleReading = $readers->security?->roles();
        // The row-level security state of the tables the PROJECT named, and the grants, read over the
        // same session. Held in variables rather than passed inline because each reading knows what it
        // could NOT read, and those skips have to reach the report: a run that dropped them would
        // answer from a partial reading and look exactly like one that read everything.
        $grantReading = $readers->security?->grants();
        $rlsReading = $readers->security?->rlsStates();
        // The host-based authentication rules, read on the same terms. MySQL has no such file and
        // answers `unsupported()` rather than a refusal — a distinction the subjects carry so the
        // five HBA rules stay silent there without any of them knowing what engine it is.
        $hbaReading = $readers->security?->hbaRules();
        // The stored routines, on the same terms. A routine that runs as its owner is a privilege
        // escalation wearing an ordinary name, and the grants already read say only who may call it.
        $routineReading = $readers->security?->routines();
        $security = $readers->security instanceof SecurityReader
            && $roleReading instanceof RoleReading
            && $grantReading instanceof GrantReading
            && $rlsReading instanceof RlsReading
            && $hbaReading instanceof HbaReading
            && $routineReading instanceof RoutineReading
            ? SecuritySubjects::fromReadings(
                $roleReading,
                $grantReading,
                $rlsReading,
                $hbaReading,
                $routineReading,
                $context,
                // The project's own statement about which connection is which, resolved once here. The
                // rules read it off the subject rather than out of the container, so the awkward states
                // — nothing configured, both the same, a name that resolves to nothing — are states a
                // test can put them in.
                $this->connectionSeparation($roleReading, $connection),
            )
            : [];

        // What the security reading was refused, in ONE list. Degradation is the normal case on a
        // managed instance, and a report that carried the findings of a partial reading without
        // carrying its gaps would be the silent green this package exists to prevent.
        // `->` rather than `?->`: `??` already yields null for a property read on null, so the
        // nullsafe operator in front of it says nothing the coalesce does not.
        $securitySkips = [
            ...($roleReading->skips ?? []),
            ...($grantReading->skips ?? []),
            ...($rlsReading->skips ?? []),
            ...($hbaReading->skips ?? []),
            ...($routineReading->skips ?? []),
        ];

        // Gated on the version the SERVER reported, never on a configured pin. A pin is a
        // determinism aid for a lint run over files; against a live instance the instance is the
        // authority, and gating on a pin would silence a rule the server actually needs — or run
        // one it cannot support — while the report claimed the pinned version all along.
        //
        $selected = $this->activeRules($target, $activeLevel, $selectedCategories);
        $versionGate = new AuditVersionGate($this->serverVersion($target));
        $rules = $versionGate->applicable($selected);

        // What the version gate held back, and why. Reported rather than merely absent: a rule set
        // that shrinks against an older server produces a shorter report in which every finding is
        // still true and nothing says a check was skipped — the silent green in its purest form.
        $versionWithheld = $versionGate->withheld($selected);

        // Split by what this INSTANCE can answer, not by what the rule set contains. A rule scoped
        // to the write path reads perfectly well on a replica — that is exactly the trap — and the
        // value it returns describes the replica. Withheld rules are reported one notice each rather
        // than dropped: a check that did not run and a check that passed are the same silence, and
        // on a replica that silence reads as "the server settings are fine".
        $answerable = array_values(array_filter($rules, fn (Rule $rule): bool => ! $this->withheldHere($rule, $target)));
        $withheld = array_values(array_filter($rules, fn (Rule $rule): bool => $this->withheldHere($rule, $target)));

        // Read whatever the project configured, ALWAYS — the bypass decides whether it is applied,
        // never whether it is read. A run that skipped the read could not tell "there was nothing
        // to bypass" from "the bypass worked", and those are opposite facts behind one report.
        $baseline = new ConfiguredBaseline($this->config)->forRun();

        // Kept as its own value rather than spread inline below, because this run has TWO answers
        // to report and only one of them is a finding: which rules were asked is a fact about the
        // run, and it has to survive into the header even when nothing came back.
        $judged = $this->judge($answerable, [
            ...$snapshot->objects,
            ...SettingSubjects::fromReading($settings, $context, $crossFacts, $pooler),
            ...$security,
        ]);

        $findings = [
            ...$this->pinFindings($target, $context),
            ...$this->poolerFindings($target, $context),
            ...$this->divergenceFindings($target, $context),
            ...$this->skipFindings($snapshot, $target, $context),
            ...$this->securitySkipFindings($securitySkips, $target, $context),
            ...$this->versionSkewFindings($target, $context),
            ...$this->belowFloorFindings($target, $context),
            ...$this->orphanedIgnoreFindings($snapshot, $target, $activeCategories, $overrides),
            // Only when the flag was given AND there was genuinely nothing to bypass. Before the
            // audit could read a baseline at all this fired on every such run, which was honest
            // then and would be a lie now: a project with a real baseline would be told its
            // emergency exit had nothing to open while the exit was doing exactly its job.
            ...($ignoreBaseline && $baseline->entries === []
                ? [AuditNotices::baselineBypassHadNothingToBypass($this->runContext($activeLevel, 0, $overrides, $activeCategories, $target))]
                : []),
            ...$this->settingsFindings($settings, $target, $context),
            ...array_map(
                static fn (Rule $rule): Finding => AuditNotices::withheldByInstanceScope($rule, $target, $context),
                $withheld,
            ),
            ...array_map(
                fn (string $reason, string $ruleId): Finding => AuditNotices::withheldByVersion(
                    $ruleId,
                    $reason,
                    $this->serverVersion($target) instanceof ServerVersion,
                    $target,
                    $context,
                ),
                $versionWithheld,
                array_keys($versionWithheld),
            ),
            // The third reason a rule can be absent, and the only one this PACKAGE chose. Its two
            // siblings above report what the instance cannot answer; this one reports what SQLens
            // retired. Without it a deprecation makes the report shorter and everything left in it
            // is still true — indistinguishable from a database that got healthier.
            ...array_map(
                static fn (Rule $rule): Finding => AuditNotices::withheldByDeprecation($rule, $target, $context),
                $this->deprecatedRulesInScope($target, $activeLevel, $selectedCategories),
            ),
            ...$judged->findings,
        ];

        if ($rules === []) {
            // The EFFECTIVE scope, not the flag. A project that narrowed its audit in
            // `config/sqlens.php` and filtered every rule away gets the same sentence naming the
            // same categories as one that passed --category, because the reader's next move is
            // identical and "no rule is active at level 4" without the why sends them to the wrong
            // file.
            $findings[] = AuditNotices::noActiveRules($activeLevel, $activeCategories, $target, $context);
        }

        // The debt account, read against the live catalog. It runs HERE — after every rule has
        // spoken and before `outcome()` applies suppression — for the same reason the lint pass
        // sits where it does: a debt finding is a finding, and it goes through the same baseline,
        // ignore list, gates and ordering as every other one.
        $findings = [...$findings, ...$this->debtFindings($target, $session, $context, $debt)];

        // A scope that admits no rule is a MISCONFIGURATION, not a clean run. The finding alone
        // would not be enough: an undetermined only moves the exit code under strict_undetermined,
        // so without this a CI job branching on the code would read "nothing was checked" as a
        // pass — which is the exact silent green the finding exists to prevent, arriving one layer
        // further out.
        return $this->outcome(
            $target,
            $context,
            $activeLevel,
            // What actually ran. A withheld rule did not check anything, and counting it would let
            // a replica audit report the same "12 rules active" as a primary one over a report that
            // judged nothing.
            count($answerable),
            $findings,
            $overrides,
            $activeCategories,
            misconfigured: $rules === [],
            skips: [...$this->reportedSkips($snapshot), ...$this->reportedSecuritySkips($securitySkips)],
            // The switch is applied HERE, where it was read, and never inside the reader or the
            // outcome: those two answer "what does the project have" and "what did this run see",
            // and folding a flag into either makes one of them unable to answer its own question.
            baseline: $ignoreBaseline ? BaselineFile::of([]) : $baseline,
            // The measured half of the header's rule accounting. `count($answerable)` above says how
            // many rules this run SELECTED; this says which of them were actually handed something
            // to judge, and the gap between the two is a check that did not happen.
            evaluatedRuleIds: $judged->evaluatedRuleIds,
        );
    }

    /**
     * Ignore patterns that matched nothing in what this run actually read.
     *
     * Compared against the SNAPSHOT rather than against the catalog at large: the answer has to be
     * about the objects this audit looked at, or a pattern scoped to a schema the run did not
     * cover would be reported as rotten every time.
     *
     * @param  list<string>  $activeCategories
     * @return list<Finding>
     */
    private function orphanedIgnoreFindings(CatalogSnapshot $snapshot, InstanceTarget $target, array $activeCategories, RunOverrides $overrides): array
    {
        $ignore = IgnoreList::fromConfig(
            $this->config->get('sqlens.audit.ignore'),
            is_string($prefix = $this->config->get('database.connections.'.$target->connection.'.prefix')) ? $prefix : '',
        );

        // The snapshot's objects are already schema objects — PHPStan says so, and a defensive
        // filter here would be a branch nothing can reach.
        $paths = [];

        foreach ($snapshot->objects as $object) {
            $paths[] = $object->qualifiedName;

            // …and a ROUTINE gets a second spelling, because it has two and a user only ever sees
            // one of them. The catalog key carries the identity arguments, since PostgreSQL
            // overloads: `public.fee(integer)` and `public.fee(numeric)` are two objects with one
            // name, and a key without the arguments would make them one. A FINDING about that
            // routine is located at the BARE name, so a suppression copied out of a report reads
            // `public.fee`.
            //
            // With only the parenthesized spelling in this list, that suppression silenced the
            // finding correctly AND was reported as orphaned debt in the same run — the run
            // contradicting itself about the same pattern. Measured on
            // `sqlens_fixture.sensitive_total`, whose finding is located at the bare name while the
            // catalog holds `sqlens_fixture.sensitive_total()`.
            //
            // Both spellings are offered rather than one replaced: a project that wrote the precise,
            // overload-aware pattern must keep working, and it is the only way to silence one
            // overload and not the other.
            if ($object->type === SchemaObjectType::Routine && ($parenthesis = strpos($object->qualifiedName, '(')) !== false) {
                $paths[] = substr($object->qualifiedName, 0, $parenthesis);
            }
        }

        $orphans = $ignore->orphanedObjectPatterns($paths);

        return $orphans === []
            ? []
            : [AuditNotices::orphanedIgnorePatterns($orphans, $this->runContext($this->configuredLevel(), 0, $overrides, $activeCategories, $target))];
    }

    /**
     * The pin the project set, when it disagrees with the instance that answered.
     *
     * Empty in every other case — no pin, an unreadable pin, no version from the server, or the two
     * agreeing. The unreadable pin is deliberately silent HERE rather than reported twice: the lint
     * runner already has a notice for that, and it is a different complaint (the value could not be
     * read) from this one (the value was read and is wrong).
     *
     * @return list<Finding>
     */
    private function versionSkewFindings(InstanceTarget $target, SubjectContext $context): array
    {
        $pinned = $this->config->get('sqlens.assume_server_version');
        $detected = $this->serverVersion($target);

        if (! is_string($pinned) || $pinned === '' || ! $detected instanceof ServerVersion) {
            return [];
        }

        $parsed = ServerVersion::parsePin($pinned, $target->driver);

        if (! $parsed instanceof ServerVersion || $parsed->toString() === $detected->toString()) {
            return [];
        }

        return [AuditNotices::assumedVersionSkew($parsed->toString(), $detected->toString(), $target, $context)];
    }

    /**
     * The supported-version floor, judged against the instance that actually answered.
     *
     * The RAW banner goes in, never the parsed form: MariaDB reports `5.5.68-MariaDB` from
     * `version()`, which parses to 5.5.68 and lands below the 8.4 floor — so a parsed input
     * would tell a MariaDB operator to upgrade a MySQL they do not run. The floor unit refuses
     * to judge a banner it cannot attribute, and it can only do that if it sees the original.
     *
     * Recomputed from the target rather than threaded, for the same reason the server version
     * beside it is: it is a pure derivation, and threading it would put the same fact in two
     * places that can disagree.
     *
     * @return list<Finding>
     */
    private function belowFloorFindings(InstanceTarget $target, SubjectContext $context): array
    {
        $banner = $target->identity?->serverVersion;
        $driver = $this->drivers->resolve($target->driver);

        if (! is_string($banner) || $banner === '' || ! $driver instanceof Driver) {
            return [];
        }

        $failure = new ServerVersionFloor()->check($driver, $banner);

        return $failure instanceof DriverResolutionFailure
            ? [AuditNotices::serverBelowFloor($failure, $target, $context)]
            : [];
    }

    /**
     * The reader's skips, flattened for the header.
     *
     * They are already findings — {@see skipFindings()} turns each into a named `undetermined` —
     * and they appear in the header TOO, on purpose. A reader scanning a clean summary has no way
     * to tell a run that found nothing from one that could not look, and the second is the one
     * that needs a grant fixed. The duplication is the point rather than an oversight.
     *
     * @return list<ReportedSkip>
     */
    private function reportedSkips(CatalogSnapshot $snapshot): array
    {
        return array_map(
            static fn (CatalogSkip $skip): ReportedSkip => new ReportedSkip(
                area: $skip->type->value.' '.$skip->reference,
                reason: $skip->reason->value,
                // The error code sharpens an unexpected failure; for the ordinary reasons there is
                // none, and the reader's own words are the better detail.
                detail: $skip->errorCode ?? $skip->detail,
            ),
            $snapshot->skips,
        );
    }

    /**
     * How many rules this driver registers for the AUDIT suite, before any gate.
     *
     * The denominator behind the header's hidden count, read from the same place
     * {@see self::activeRules()} starts from — a second source would let the two disagree, and the
     * symptom would be a header whose two numbers do not add up to anything.
     */
    private function auditRuleCount(InstanceTarget $target): int
    {
        // The driver's WHOLE audit set, deliberately BEFORE the privacy pack's switch — because this
        // number is the base the header's `hidden-rules` is subtracted from, and a rule the switch
        // withheld is the definition of a rule that did not apply.
        //
        // Counting the filtered set instead made a switched-off rule neither active NOR hidden:
        // `active + hidden` came to 61 over a driver registering 62, so the one rule the privacy
        // switch withheld appeared in no column at all. A reader who then turns the pack on gets
        // more rules than the header ever admitted existed — which is the exact thing `hidden-rules`
        // was added to prevent, in the one place the package advertises the opposite.
        //
        // Assembly still skips them, and that is untouched: they cost no query and no time. What
        // changes is only that the report ADMITS they exist.
        $driver = $this->drivers->resolve($target->driver);

        return count(array_filter(
            $driver instanceof Driver ? [...$driver->rules()] : [],
            static fn (Rule $rule): bool => in_array(Suite::Audit, $rule->suites(), true),
        ));
    }

    /**
     * This driver's rules, filtered to the audit suite.
     *
     * @return list<Rule>
     */
    private function suiteRules(InstanceTarget $target): array
    {
        $driver = $this->drivers->resolve($target->driver);

        $suiteRules = array_values(array_filter(
            $driver instanceof Driver ? [...$driver->rules()] : [],
            static fn (Rule $rule): bool => in_array(Suite::Audit, $rule->suites(), true),
        ));

        // The privacy pack's switch, applied where rules are ASSEMBLED rather than where they are
        // evaluated. Off, its rules never enter the registry at all — they cost no query and no
        // time, because the run does not carry them and skip them, it does not have them. The run
        // still reports which categories were active, so "checked and found nothing" stays
        // distinguishable from "was never asked".
        return new PrivacyPack($this->config)->admitted($suiteRules);
    }

    /**
     * Every rule this run will apply, in a fixed order.
     *
     * Sorted by id at the end, so the ORDER a rule was registered in cannot reach the report. Two
     * runs of an unchanged project must produce byte-identical output, and a finding order that
     * followed registration would break that the first time somebody reordered a rule set.
     *
     * @param  list<Category>  $categories  the resolved scope, empty meaning every category
     * @return list<Rule>
     */
    private function activeRules(InstanceTarget $target, int $level, array $categories): array
    {
        return $this->narrowed(RuleRegistry::fromRules($this->suiteRules($target))->executable(), $level, $categories);
    }

    /**
     * The deprecated rules THIS run would otherwise have applied.
     *
     * Narrowed through the very same three axes as the active set, and that is the whole point:
     * announcing every deprecated rule in the package would be noise on a run that was never going
     * to reach them, while announcing none is the silence the notice exists to break. What is
     * reported is exactly the set whose absence changes this report.
     *
     * @param  list<Category>  $categories
     * @return list<Rule>
     */
    private function deprecatedRulesInScope(InstanceTarget $target, int $level, array $categories): array
    {
        return $this->narrowed(RuleRegistry::fromRules($this->suiteRules($target))->deprecated(), $level, $categories);
    }

    /**
     * The three narrowing axes, applied to whichever starting set a caller brings.
     *
     * One path rather than two, deliberately. The active set and the deprecated-in-scope set have to
     * answer the same question — "would this run have reached the rule" — and a second copy of the
     * chain would drift the first time a fourth axis is added, in the direction that reads as
     * success: the notice would quietly stop mentioning rules the run really did drop.
     *
     * @param  list<Rule>  $candidates
     * @param  list<Category>  $categories
     * @return list<Rule>
     */
    private function narrowed(array $candidates, int $level, array $categories): array
    {
        $leveled = new LevelGate(Level::from($level))->admitting($candidates);

        $scoped = new CategoryFilter($categories)->apply($leveled);

        // The maturity axis, last of the three and the only one whose empty default is the STRICT
        // reading: an unconfigured stability list admits stable rules only. Without this the tier
        // traveled into the report and changed nothing on the way — the report showed `preview`
        // beside a finding that had already failed the build.
        $settled = StabilityGate::fromConfig($this->config->get('sqlens.stability'))->apply($scoped);

        usort($settled, static fn (Rule $a, Rule $b): int => $a->id() <=> $b->id());

        return $settled;
    }

    /**
     * Whether this rule's verdict cannot be placed on the instance that answered.
     *
     * Both halves are required and neither is sufficient: a replica is a fine place to judge a
     * schema, and a primary is a fine place to judge anything. An UNDETERMINED role withholds
     * exactly as a replica does — a verdict nobody can place is worth as much as one placed on the
     * wrong machine, which is the rule {@see InstanceRole::answersForTheWritePath()} already encodes.
     */
    private function withheldHere(Rule $rule, InstanceTarget $target): bool
    {
        return $rule->instanceScope()->needsTheWritePath() && ! $target->role()->answersForTheWritePath();
    }

    /**
     * Every rule's verdict over every object it applies to, and which rules were asked.
     *
     * Takes the SUBJECTS rather than the snapshot, because a run judges more than the schema: the
     * server's own settings arrive as subjects of the same shape and go down the same path. Handing
     * this the snapshot would have forced a second loop for a second subject source, and the second
     * loop is where the two would drift on which rules get asked.
     *
     * @param  list<Rule>  $rules
     * @param  list<SchemaObject>  $subjects
     */
    private function judge(array $rules, array $subjects): RuleEvaluation
    {
        return RuleEvaluation::of($rules, $subjects);
    }

    /**
     * Which connection serves requests, which deploys migrations, and the role the first one uses.
     *
     * The role comes from the READING rather than from a second connection: the audit already knows
     * which account it authenticated as, and opening another connection to ask would be a second
     * answer to a question this run has answered.
     */
    private function connectionSeparation(RoleReading $roles, ?string $audited): ConnectionSeparation
    {
        $runtime = $this->config->get('sqlens.security.runtime_connection');
        $migration = $this->config->get('sqlens.security.migration_connection');

        $connected = null;

        foreach ($roles->roles as $role) {
            if ($role->connectionRole) {
                $connected = $role->identity();
            }
        }

        $runtimeName = is_string($runtime) && $runtime !== '' ? $runtime : null;
        $migrationName = is_string($migration) && $migration !== '' ? $migration : null;

        return new ConnectionSeparation(
            $runtimeName,
            $migrationName,
            $connected,
            $this->connectionIdentity($runtimeName),
            $this->connectionIdentity($migrationName),
            // WHICH connection this run addressed, threaded from the command rather than inferred.
            // Without it `runtimeRole` is whatever account the run logged in as, and a rule judging
            // that account would name the migration role as the runtime one.
            $audited,
        );
    }

    /**
     * WHO a named connection authenticates as — `user@host/database` — or null when it does not say.
     *
     * Two entries in config/database.php are two NAMES, and a project that filed a second one
     * believes it has taken the single most effective measure there is. Whether it has depends on
     * the credentials underneath, and that is the only place they can be read from.
     *
     * Null rather than a partial string when any part is missing, and that is the load-bearing half:
     * credentials resolved from the environment at runtime leave every field empty here, and two
     * empty fingerprints compare EQUAL. A rule handed those would report a separation that is
     * missing on every project whose configuration is environment-driven — the loudest possible
     * false finding. Null instead makes the rule say it could not tell.
     */
    private function connectionIdentity(?string $connection): ?string
    {
        if ($connection === null) {
            return null;
        }

        $parts = [];

        foreach (['username', 'host', 'database'] as $key) {
            $value = $this->config->get('database.connections.'.$connection.'.'.$key);

            if (! is_string($value) || $value === '') {
                return null;
            }

            $parts[] = $value;
        }

        return sprintf('%s@%s/%s', ...$parts);
    }

    /**
     * The one thing a failed settings reading must not do: nothing.
     *
     * A per-variable refusal is the rules' business — they report `undetermined` for their own
     * variable. This is the whole reading failing, which would otherwise leave every server-baseline
     * rule subject-less and therefore silent, and silence is what a correctly configured server
     * produces too.
     *
     * @return list<Finding>
     */
    private function settingsFindings(SettingsReading $settings, InstanceTarget $target, SubjectContext $context): array
    {
        $reason = $settings->absenceReason();

        return $reason instanceof UndeterminedReason
            ? [AuditNotices::settingsUnreadable($reason, $settings->failureDetail, $target, $context)]
            : [];
    }

    /**
     * What the reading could not see, carried into the result.
     *
     * A skip that stayed in the snapshot would make an incomplete audit indistinguishable from a
     * complete one — the silent green this package refuses, arriving through an absence rather than
     * through a wrong answer.
     *
     * @return list<Finding>
     */
    private function skipFindings(CatalogSnapshot $snapshot, InstanceTarget $target, SubjectContext $context): array
    {
        return array_map(
            static fn (CatalogSkip $skip): Finding => AuditNotices::skipped($skip, $target, $context),
            $snapshot->skips,
        );
    }

    /**
     * The same statement for the SECURITY reading, under its own family.
     *
     * Separate from the catalog's because the two cover disjoint readings and a consumer acts on them
     * differently: what a managed provider withholds from the security catalog is a standing fact to
     * baseline once, where a gap in the schema reading is usually a grant somebody can fix.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<Finding>
     */
    private function securitySkipFindings(array $skips, InstanceTarget $target, SubjectContext $context): array
    {
        return array_map(
            static fn (CatalogSkip $skip): Finding => AuditNotices::securitySkipped($skip, $target, $context),
            $skips,
        );
    }

    /**
     * The security reading's gaps for the HEADER, which is what gets read first.
     *
     * @param  list<CatalogSkip>  $skips
     * @return list<ReportedSkip>
     */
    private function reportedSecuritySkips(array $skips): array
    {
        return array_map(
            static fn (CatalogSkip $skip): ReportedSkip => new ReportedSkip(
                $skip->reference,
                $skip->reason->value,
                $skip->detail,
            ),
            $skips,
        );
    }

    /**
     * The pin could not be confirmed — said out loud rather than passed over.
     *
     * A pinned NAME against an observed ADDRESS is the ordinary case, not an edge, and SQLens will
     * not resolve one to compare them: that would be a network call and a second source of truth
     * inside a run whose contract is that the same state gives the same result. So the check is
     * reported as the thing it is — one that could not run — and the run continues.
     *
     * @return list<Finding>
     */
    private function pinFindings(InstanceTarget $target, SubjectContext $context): array
    {
        return $target->pinVerdict() === PinVerdict::Unverifiable
            ? [AuditNotices::unverifiablePin($target, $context)]
            : [];
    }

    /**
     * The topology could not be established, or was established as multiplexed — said once, at run
     * level, on top of what each instance-scoped rule reports for itself.
     *
     * Both are worth a sentence of their own because the per-rule findings explain why ONE check
     * was withheld, and this explains why a whole band of them was. A reader seeing fifteen
     * undetermined settings deserves the single cause rather than fifteen copies of it.
     *
     * @return list<Finding>
     */
    private function poolerFindings(InstanceTarget $target, SubjectContext $context): array
    {
        return $target->pooler instanceof PoolerReading && $target->pooler->degradesInstanceScope()
            ? [AuditNotices::pooledConnection($target, $context)]
            : [];
    }

    /**
     * The run stops: the connection could not be opened, so nothing was read.
     *
     * NOT flagged as misconfigured, and that is a judgment rather than an omission: a connection
     * that will not open is a wrong host, a rotated password, a firewall, or a server that is
     * simply down, and this package cannot tell those apart. Calling all four a misconfiguration
     * would tell an operator whose database is restarting to go and fix their config file.
     *
     * So it goes out as undetermined and takes the exit code the contract already assigns to that:
     * 3 under `--strict`, 0 otherwise. Never 1 — that value means findings breached a gate, and no
     * rule ever ran.
     *
     * @param  list<string>  $activeCategories
     */
    private function unreachable(
        InstanceTarget $target,
        SubjectContext $context,
        Throwable $error,
        int $level,
        RunOverrides $overrides,
        array $activeCategories,
    ): AuditOutcome {
        return $this->outcome(
            $target,
            $context,
            $level,
            0,
            [AuditNotices::serverUnreachable(new CredentialRedactor()->redact($error->getMessage()), $target, $context)],
            $overrides,
            $activeCategories,
        );
    }

    /**
     * The engine behind the driver key is not the engine the rules were written for.
     *
     * A misconfiguration, and the same shape as the pin refusal beside it: nothing is judged,
     * and the one notice says why. Not an `undetermined` finding among a normal report —
     * every rule that ran would be reasoning about the wrong product, so there is no report
     * worth qualifying.
     *
     * @param  list<string>  $activeCategories
     */
    private function refusedEngine(DriverResolutionFailure $failure, InstanceTarget $target, SubjectContext $context, int $level, RunOverrides $overrides, array $activeCategories): AuditOutcome
    {
        return $this->outcome(
            $target,
            $context,
            $level,
            0,
            [AuditNotices::unsupportedEngine($failure, $target, $context)],
            $overrides,
            $activeCategories,
            misconfigured: true,
        );
    }

    /**
     * The run stops: the server that answered is not the one that was pinned.
     *
     * @param  list<string>  $activeCategories
     */
    private function refusedPin(InstanceTarget $target, SubjectContext $context, int $level, RunOverrides $overrides, array $activeCategories): AuditOutcome
    {
        return $this->outcome(
            $target,
            $context,
            $level,
            0,
            [AuditNotices::divergentPin($target, $context)],
            $overrides,
            $activeCategories,
            misconfigured: true,
        );
    }

    /**
     * Where the configuration and the server disagreed.
     *
     * A finding, not a log line: an audit run against a different instance than the operator meant
     * is not a detail, and the deploy pipeline reading the JSON has to be able to see it.
     *
     * @return list<Finding>
     */
    private function divergenceFindings(InstanceTarget $target, SubjectContext $context): array
    {
        return $target->divergences() === []
            ? []
            : [AuditNotices::instanceDivergence($target, $context)];
    }

    /**
     * The version the server reported, parsed — or null when it did not report one.
     *
     * Null is not "assume the newest". A rule with a version window and no version to check it
     * against is withheld with a named reason, which is the honest answer: a run that guessed would
     * either apply a rule the server cannot support or silence one it needs, and either way the
     * report would not say so.
     */
    private function serverVersion(InstanceTarget $target): ?ServerVersion
    {
        $raw = $target->identity?->serverVersion;
        // One expression, deliberately: "the server reported nothing" and "what it reported did not
        // parse" are the same answer here — no version to gate on — and two branches would leave
        // the rarer one unreachable in a run that got far enough to read a catalog at all.
        $parsed = $raw === null ? null : ServerVersion::parse($raw, $target->driver);

        return $parsed instanceof ServerVersion ? $parsed : null;
    }

    private function request(): CatalogRequest
    {
        $schemas = $this->config->get('sqlens.catalog.schemas');

        return new CatalogRequest(schemas: is_array($schemas) ? array_values(array_filter($schemas, is_string(...))) : []);
    }

    private function configuredLevel(): int
    {
        $level = $this->config->get('sqlens.level');

        return is_numeric($level) && (int) $level >= 0 && (int) $level <= 9 ? (int) $level : 0;
    }

    private function subjectContext(InstanceTarget $target, RunOverrides $overrides): SubjectContext
    {
        $profile = $this->config->get('sqlens.profile');

        return new SubjectContext(
            driver: $target->driver,
            profile: is_string($profile) ? $profile : 'local',
            // The per-run override, resolved against the configured value. The audit used to read
            // the config directly here, so `--strict-tools` on a security run reached the lint half and
            // stopped at this line — one half strict, the other not, from a single flag.
            strictTools: $overrides->strictTools($this->config->get('sqlens.strict_tools') === true),
            connection: $target->connection,
            // On EVERY finding this run produces, not only in the header. A reader who scrolls to
            // one finding and acts on it never saw the header, and the role is part of what that
            // finding means rather than context for the run around it.
            instanceRole: $target->role()->value,
        );
    }

    /**
     * A refusal when the project's tenancy is undeclared or half-declared, or null to carry on.
     *
     * Two distinct states, two messages. A project that never answered is told what the signals
     * were, because "this looks multi-tenant" without them is an assertion the reader cannot
     * check — and the heuristic is allowed to be wrong, so "those signals are mistaken" has to be
     * an answer somebody can give. A project that answered `explicit` and named nobody is told the
     * other thing: it already knows it has tenants.
     *
     * ## All three signals, and where the third one comes from
     *
     * `tenancy.database.prefix` is another package's config key — stancl/tenancy's, the most widely
     * deployed of them. Reading it is deliberate rather than presumptuous: SQLens has no such key of
     * its own, and the fact being looked for is precisely one that somebody wrote down in THAT file.
     * It costs one config read, it cannot fire on a project that has no tenancy config at all, and
     * it catches the setup the connection-shaped signal cannot — a project that switches one
     * connection's database per tenant has a single entry under `database.connections`.
     *
     * @param  list<string>  $activeCategories
     */
    private function tenancyRefusal(?int $level, RunOverrides $overrides, array $activeCategories): ?AuditOutcome
    {
        $mode = $this->config->get('sqlens.audit.tenancy.mode');
        $reference = $this->config->get('sqlens.audit.tenancy.reference');
        $context = $this->runContext($level ?? $this->configuredLevel(), 0, $overrides, $activeCategories);

        if ($mode === 'explicit') {
            return is_string($reference) && trim($reference) !== ''
                ? null
                : $this->refusedTenancy(AuditNotices::tenancyReferenceMissing($context), $context, $overrides);
        }

        $connections = $this->config->get('database.connections');
        $signals = TenancySignals::detect(
            is_array($connections) ? $connections : [],
            $this->manifest->requiredPackages(),
            $this->config->get('tenancy.database.prefix'),
        );

        return $signals->found()
            ? $this->refusedTenancy(AuditNotices::tenancyNotDeclared($signals->describe(), $context), $context, $overrides)
            : null;
    }

    private function refusedTenancy(Finding $notice, RunContext $context, RunOverrides $overrides): AuditOutcome
    {
        return new AuditOutcome(
            Result::of([$notice], $this->metadata($overrides)),
            $context,
            ExitCode::Misconfiguration,
            is_string($configured = $this->config->get('sqlens.connection')) ? $configured : 'unresolved',
        );
    }

    /**
     * The unknown rule ids in the audit ignore list, as configuration violations.
     *
     * Routed through the SAME validator the lint side has rather than a second one: rule ids are
     * public API, the comparison is exact, and two validators would eventually disagree about what
     * "known" means. The suggestion it offers is offered and never applied — a validator that
     * helpfully accepted a near-miss would make the id set unknowable, and the next release that
     * changed the folding would silently un-suppress findings.
     *
     * @return list<ConfigViolation>
     */
    private function ignoreListViolations(): array
    {
        $ignore = IgnoreList::fromConfig($this->config->get('sqlens.audit.ignore'));

        if ($ignore->isEmpty()) {
            return [];
        }

        $all = $this->allRules();

        $references = array_map(
            static fn (array $reference): RuleIdReference => RuleIdReference::inAuditIgnore(
                $reference['ruleId'],
                $reference['form'],
                $reference['index'],
            ),
            $ignore->ruleReferences(),
        );

        // Checked against EVERY rule, not just the audit ones. An id that names a real lint rule
        // is a different mistake from an id that names nothing, and validating against the audit
        // set alone would collapse the two — telling somebody their correctly spelled id is
        // unknown, and sending them hunting a typo that is not there.
        // …and against the external tools' declared ids too, which are NOT Rule objects. They come
        // from the shipped map rather than from a running binary: a suppression naming a tool rule
        // has to stay valid on a machine where the tool is absent, disabled, or unbuildable, or a
        // correct configuration would fail on a laptop and pass in CI.
        // …and the tools' own namespaces, DERIVED from the drivers rather than listed. Until this
        // was threaded through, `PGLS.*` was refused everywhere: the `alsoKnown` set carried
        // squawk's mapped ids alone, so a pgls rule could not be named in a suppression at all.
        $validator = new RuleIdValidator(
            RuleRegistry::fromRules($all),
            SquawkRuleIds::suppressible(),
            $this->drivers->everyToolPrefix(),
        );

        $violations = $validator->unknown($references);

        foreach ($references as $reference) {
            $rule = $all[$reference->ruleId] ?? null;

            if ($rule instanceof Rule && ! in_array(Suite::Audit, $rule->suites(), true)) {
                $violations[] = ConfigViolation::ruleNotInSuite(
                    $reference->describe(),
                    $reference->ruleId,
                    Suite::Audit->value,
                    implode(', ', array_map(static fn (Suite $suite): string => $suite->value, $rule->suites())),
                );
            }
        }

        return $violations;
    }

    /**
     * The baseline's own rule ids, checked before anything connects.
     *
     * A baseline entry naming a rule that does not exist suppresses nothing and says nothing — and
     * unlike an ignore list it cannot be noticed from the output, because an entry that matches
     * nothing produces exactly what a matching entry produces once the code is fixed. The line stays
     * in the file and reads as a decision that is still holding.
     *
     * Skipped when the run was told to IGNORE the baseline: that flag is the emergency exit, and an
     * exit that refuses to open because the thing it bypasses has a typo in it is not an exit.
     *
     * @return list<ConfigViolation>
     */
    private function baselineViolations(bool $ignoreBaseline): array
    {
        if ($ignoreBaseline) {
            return [];
        }

        try {
            $baseline = new ConfiguredBaseline($this->config)->forRun();
        } catch (UnreadableBaseline) {
            // A baseline that cannot be READ has its own refusal, further down and with its own
            // message. Answering it here would replace "this file is unparseable" with "its rule ids
            // could not be checked" — the less useful half of the same news, arriving first.
            return [];
        }

        return BaselineRuleIds::violations($baseline, $this->allRules());
    }

    /**
     * Every rule of every registered driver, keyed by id.
     *
     * Across drivers because an ignore list is written before a connection is resolved, and across
     * SUITES because the two ways an id can be wrong — it names nothing, or it names something
     * that does not run here — need different messages, and only the full set can tell them apart.
     *
     * @return array<string, Rule>
     */
    private function allRules(): array
    {
        $rules = [];

        foreach ($this->drivers->all() as $driver) {
            foreach ($driver->rules() as $rule) {
                $rules[$rule->id()] = $rule;
            }
        }

        return $rules;
    }

    /**
     * A run refused before it connected, because the configuration named a rule that does not
     * exist.
     *
     * Its own path rather than the instance-resolution one: they fail for unrelated reasons and a
     * shared message would describe neither. The exit code is the same because both are the same
     * class of problem — nothing was audited, and the fix is in a file rather than in a database.
     *
     * @param  list<ConfigViolation>  $violations
     * @param  list<string>  $activeCategories
     */
    private function refusedConfig(array $violations, ?int $level, RunOverrides $overrides, array $activeCategories): AuditOutcome
    {
        $context = $this->runContext($level ?? $this->configuredLevel(), 0, $overrides, $activeCategories);

        $findings = array_map(
            static fn (ConfigViolation $violation): Finding => AuditNotices::invalidIgnoreList($violation, $context),
            $violations,
        );

        return new AuditOutcome(
            Result::of($findings, $this->metadata($overrides)),
            $context,
            ExitCode::Misconfiguration,
            is_string($configured = $this->config->get('sqlens.connection')) ? $configured : 'unresolved',
        );
    }

    /**
     * A run that never addressed an instance — refused before anything connected.
     *
     * @param  list<string>  $activeCategories
     */
    private function refused(InstanceResolution $resolution, ?int $level, RunOverrides $overrides, array $activeCategories): AuditOutcome
    {
        $context = $this->runContext($level ?? $this->configuredLevel(), 0, $overrides, $activeCategories);
        $findings = match (true) {
            $resolution->ambiguous => [AuditNotices::ambiguousInstance($resolution->candidates, $context)],
            $resolution->ambiguousHosts => [AuditNotices::ambiguousReadHosts($resolution->hosts, $context)],
            $resolution->unofferedHost !== null => [AuditNotices::unofferedHost($resolution->unofferedHost, $resolution->hosts, $context)],
            default => [],
        };

        $result = Result::of($findings, $this->metadata($overrides));

        return new AuditOutcome(
            $result,
            $context,
            ExitCode::Misconfiguration,
            $resolution->candidates[0] ?? 'unresolved',
            $resolution->unsupported,
        );
    }

    /**
     * What the committed debt account and the live catalog say about each other, as findings.
     *
     * Silent when the project has not adopted the account. Otherwise every recorded debt gets one of
     * three answers, and the third — the object could not be found — is REPORTED rather than quietly
     * treated as settled: a dropped table, a schema this run never looked at, and a role without the
     * privilege all look identical from here, and none of them is a paid debt.
     *
     * ## Why the "still owed" reading is borrowed rather than written
     *
     * {@see PostdeployVerifier} holds the one reader of each catalog column a debt is about. Asking
     * it here — rather than writing a second query — is what keeps this command and the deploy
     * commands from answering differently about one database. The name reads oddly from the audit
     * route; the alternative is a determinism break, which is worse than an odd name.
     *
     * @return list<Finding>
     */
    private function debtFindings(InstanceTarget $target, DatabaseConnection $connection, SubjectContext $context, DebtMode $debt): array
    {
        if ($this->config->get('sqlens.deploy.debt.enabled') !== true) {
            return [];
        }

        $configured = $this->config->get('sqlens.deploy.debt.path');
        $path = is_string($configured) && $configured !== '' ? $configured : DebtLedger::DEFAULT_PATH;
        $ledger = DebtLedger::load(new Filesystem, $this->manifest->root().'/'.$path);

        if (! $ledger->isUsable()) {
            return [DebtNotices::ledgerUnreadable(
                $ledger->refusal instanceof DebtLedgerRefusal ? $ledger->refusal->detail : 'it could not be read',
                $ledger->refusal instanceof DebtLedgerRefusal ? $ledger->refusal->reason : UndeterminedReason::DebtLedgerUnreadable,
                $target->driver,
                $target->connection,
                $context,
            )];
        }

        $version = $this->serverVersion($target);

        // No resolved server version means the checks below cannot be built at all. The account is
        // left unread rather than half-read: a partial answer here would report debts as settled on
        // the strength of a reading that never happened.
        if (! $version instanceof ServerVersion) {
            return [];
        }

        $session = $this->connections->sessionFor($connection, $this->drivers);

        $report = $this->debtChecks->verify(new PostdeployContext(
            connection: $target->connection,
            driver: $target->driver,
            serverVersion: $version,
            session: $session,
            profile: 'audit',
            deadlineAt: hrtime(true) + self::DEBT_BUDGET_NS,
        ));

        $stillOwed = [];

        foreach ($report->findings() as $finding) {
            if (is_string($finding->location->objectName)) {
                $stillOwed[] = $finding->location->objectName;
            }
        }

        // The half of the relationship that was missing. This route has read the
        // account since it existed; what it could not do was ADD to it, and the debts only it can
        // see were therefore the ones with no date: a `NOT VALID` constraint already in the database
        // has no migration, so nothing that reads migrations will ever find it.
        //
        // The canonicalization is the SAME one the lint route uses, which is what lets one
        // constraint seen from two directions be one entry rather than two.
        $claimants = $this->debtChecks->claimants();

        $candidates = DebtRegistrar::candidates(
            $report->findings(),
            $claimants,
            $this->extensions->forDriver($target->driver),
            gmdate('Y-m-d'),
        );

        // The SCOPE, and without it this whole path would be a data-loss bug. This run reads the
        // catalog and never the migrations, so every migration-origin entry is invisible to it —
        // not absent, invisible. Reconciling unscoped would mark each of them stale and a recording
        // run would delete the half of the account it structurally cannot see.
        $reconciliation = DebtReconciliation::of(
            $ledger,
            $candidates,
            DebtRegistrar::scopeOf($claimants, DebtOrigin::Catalog),
        );

        $collected = DebtCollector::collect(
            $ledger,
            $this->drivers->debtStandingResolverFor($target->driver, $stillOwed, $session),
            gmdate('Y-m-d'),
        );

        if ($collected->ledgerMissing) {
            return [DebtNotices::ledgerMissing($path, $target->driver, $target->connection, $context)];
        }

        $thresholds = DebtThresholds::fromConfig($this->config->get('sqlens.deploy.debt.thresholds'));

        $findings = [];

        foreach ($collected->stillOpen() as $debt) {
            $findings[] = DebtNotices::stillOpen($debt, $debt->severity($thresholds, Severity::Info), $target->driver, $target->connection, $context);
        }

        foreach ($collected->resolved() as $debt) {
            $findings[] = DebtNotices::resolved($debt, $target->driver, $target->connection, $context);
        }

        foreach ($collected->unresolvable() as $debt) {
            $findings[] = DebtNotices::objectNotFound($debt, $target->driver, $target->connection, $context);
        }

        // Reported whatever the mode is. A debt the catalog shows and the account has never heard of
        // is a definite statement about the file, and a checking run that stayed silent about it
        // would leave the reader believing the account is complete.
        foreach ($reconciliation->unrecorded as $entry) {
            $findings[] = DebtNotices::unrecorded($entry, $target->driver, $target->connection, $context);
        }

        // The write, and it happens only because somebody asked for it in this invocation. The
        // default is unchanged: an ordinary audit on a deploy server edits nothing, which is the
        // property that mattered all along — not which command it is, since the same run is a
        // deploy server's on one machine and a maintainer's working copy on another and nothing in
        // the process can tell them apart.
        if ($debt === DebtMode::Record && ! $reconciliation->isSettled()) {
            DebtLedger::of($reconciliation->recorded)->write(new Filesystem, $this->manifest->root().'/'.$path);
        }

        return $findings;
    }

    /**
     * @param  list<Finding>  $findings
     * @param  list<string>  $activeCategories  the scope this run was narrowed to; empty means all
     * @param  list<ReportedSkip>  $skips  what the reading could not cover, for the header
     * @param  list<string>|null  $evaluatedRuleIds  which rules got a subject; null on a path that never dispatched
     */
    private function outcome(
        InstanceTarget $target,
        SubjectContext $subjectContext,
        int $level,
        int $activeRules,
        array $findings,
        RunOverrides $overrides,
        array $activeCategories,
        bool $misconfigured = false,
        array $skips = [],
        ?BaselineFile $baseline = null,
        ?array $evaluatedRuleIds = null,
    ): AuditOutcome {
        // Sorted by the pair a reader navigates with — where it is, then which rule said it. The
        // rule id breaks ties inside one object so two runs cannot swap two findings on one table.
        usort($findings, static fn (Finding $a, Finding $b): int => [
            $a->location->objectName ?? '', $a->ruleId,
        ] <=> [
            $b->location->objectName ?? '', $b->ruleId,
        ]);

        // Suppression AFTER the rules have spoken, never before: a runner that dropped ignored
        // findings while assembling would produce output identical to a clean audit — same
        // summary, same exit code — over a database with known problems. Routed through the shared
        // machinery instead, every hidden finding is counted and listed under the source that hid
        // it, and the header says how many.
        // The SAME baseline file and the same format the lint reads. A grown database carries a
        // stock of findings nobody clears in one sprint, and without a baseline the only tool left
        // is the ignore list — which is the wrong one: an ignore says "never applies here" and is
        // meant to stay, a baseline says "known, being paid down" and is meant to shrink. A project
        // forced to write its debt as decisions has a burn-down number that never moves.
        // Null on the refusal paths, which never got as far as reading a file: an empty baseline
        // is the honest answer there, not a second read that could fail differently.
        // Registered amplifiers, resolved ONCE for this run. The locator caches, so asking twice
        // could never disagree — but the reason to hold the list is that three separate things read
        // it below, and a filter applied at three call sites is a filter with two chances to be
        // forgotten.
        $diagnostics = $this->tools->diagnoseFor($target->driver);

        // A missing tool is never silent, even in the non-strict path: it becomes a named
        // undetermined saying what it would have added, so the run reports "fewer checks ran"
        // instead of quietly running fewer. Identical text to the lint route, from the same class.
        foreach ($diagnostics as $diagnostic) {
            if ($diagnostic->isMissing()) {
                $findings[] = MissingToolNotice::for(AuditNotice::MissingTool, $diagnostic, $target->connection, $this->manifest->root(), $subjectContext);
            }
        }

        // What each available amplifier adds, folded in AFTER the run's own rules have spoken and
        // before suppression touches anything. After the rules because the merge is one-directional
        // — a machine with a binary installed must not gate differently, beyond having more checks.
        // Before suppression because a baseline written from findings that were about to be merged
        // would pin duplicates, and every later run would carry an entry for a finding that no
        // longer exists in that shape.
        //
        // Resolved by CONTRACT, never by `instanceof`: a runner that names one tool has to be
        // edited for the second, and the edit that gets forgotten is invisible — nothing fails, the
        // tool is simply never asked.
        foreach ($diagnostics as $diagnostic) {
            $findings = $this->contributions->for($diagnostic->tool)?->contribute($findings, $diagnostic, $target->connection, $subjectContext) ?? $findings;
        }

        // Under a strict profile a FIXABLE absence is an error rather than a degradation — and
        // only a fixable one. A platform with no build for the tool fails nothing, because failing
        // a build for something nobody on that platform can install is a gate nobody can pass.
        $misconfigured = $misconfigured || ($overrides->strictTools($this->config->get('sqlens.strict_tools') === true)
            && array_any($diagnostics, static fn (ToolDiagnostic $diagnostic): bool => $diagnostic->failsStrict()));

        $suppression = SuppressionResolver::for(
            $baseline ?? BaselineFile::of([]),
            null,
            auditIgnore: IgnoreList::fromConfig(
                $this->config->get('sqlens.audit.ignore'),
                is_string($prefix = $this->config->get('database.connections.'.$target->connection.'.prefix')) ? $prefix : '',
            ),
            // Which suppression sources this run could not CHECK. It went unpassed while no tool
            // ran here, and would have become wrong the moment one did: an accepted finding from a
            // tool that never answered would be reported as stale, and somebody deleting that line
            // gets the finding back on the next machine that has the binary.
        )->resolve($this->candidates($findings), Suite::Audit, UnverifiableToolPrefixes::from($diagnostics));

        // Stale entries are carried into the Result, not dropped: a baseline line that matches
        // nothing has stopped describing what the project accepts, and a list nobody prunes is its
        // own quiet form of green.
        $result = Result::of(
            $suppression->visible,
            $this->metadata($overrides),
            $suppression->suppressed,
            $suppression->staleBaselineEntries,
        );
        $context = $this->runContext(
            $level,
            $activeRules,
            $overrides,
            $activeCategories,
            $target,
            $skips,
            max(0, $this->auditRuleCount($target) - $activeRules),
            $evaluatedRuleIds,
        );

        // A baseline entry that matched nothing is ALWAYS carried into the result above; this is the
        // second half of the answer, and it is a project's to give. `report` (the default) leaves the
        // verdict alone, because a fresh baseline on a moving codebase would otherwise fail
        // constantly. `error` is the project saying the file is meant to be kept tight — and until
        // this line existed, saying it changed nothing at all: the key validated, the run went green,
        // and somebody who set it to make a rotten baseline stop their pipeline got the silent pass
        // they had explicitly asked not to get.
        $staleBreaks = StaleBaselinePolicy::fromConfig($this->config->get('sqlens.baseline.stale'))
            ->breaks($result->staleBaselineEntries);

        return new AuditOutcome($result, $context, $this->exitCodes->resolve($result, $context, $misconfigured || $staleBreaks), $target->connection);
    }

    /**
     * Each finding paired with the fingerprint a baseline entry is matched on.
     *
     * The excerpt is empty because a catalog finding has no statement behind it — its identity is
     * the rule and the OBJECT, which is exactly what {@see FindingFingerprint} already normalizes
     * (driver, instance, object name, object type). Renaming a neighboring table therefore does
     * not move this entry, and the same table on a second instance is a different entry rather than
     * a collision.
     *
     * The ordinal disambiguates findings that share a fingerprint. It cannot happen for a catalog
     * rule today — one rule speaks once per object — but it is threaded through rather than pinned
     * to zero, so the day a second suite contributes here the entries do not silently merge.
     *
     * No annotation carrier: an audit judges a live catalog and holds no migration class, so the
     * annotation layer has nothing to read and must not appear to.
     *
     * @param  list<Finding>  $findings
     * @return list<SuppressionCandidate>
     */
    private function candidates(array $findings): array
    {
        $ordinals = [];
        $candidates = [];

        foreach ($findings as $finding) {
            $fingerprint = FindingFingerprint::of($finding->ruleId, $finding->location, Fingerprint::fromValue(''));
            $ordinal = $ordinals[$fingerprint->value] ?? 0;
            $ordinals[$fingerprint->value] = $ordinal + 1;

            $candidates[] = new SuppressionCandidate($finding, $fingerprint, $ordinal);
        }

        return $candidates;
    }

    /**
     * @param  list<string>  $activeCategories  the scope this run was narrowed to; empty means all
     * @param  list<ReportedSkip>  $skips
     * @param  list<string>|null  $evaluatedRuleIds  which rules got a subject; null when no dispatch happened
     */
    private function runContext(
        int $level,
        int $activeRules,
        RunOverrides $overrides,
        array $activeCategories,
        ?InstanceTarget $target = null,
        array $skips = [],
        int $hiddenRules = 0,
        ?array $evaluatedRuleIds = null,
    ): RunContext {
        $profile = $this->config->get('sqlens.profile');
        // Named apart from the package version below, which used to reuse this name. It worked
        // only because named arguments are evaluated top to bottom, which is not a property to
        // rest a value on.
        $serverVersion = $target?->identity?->serverVersion;

        return new RunContext(
            // The version the SERVER reported, not a pin: an audit reasons about the live
            // instance, so a pin that disagreed would describe a machine this report is not
            // about. The lint suite is the one that reasons from a pin, and it says so with
            // its own source marker.
            //
            // Testing the version alone is enough: it can only be non-null if there was a target
            // to read it from, and adding `|| $target === null` was a redundancy PHPStan named as
            // unreachable rather than as defensive.
            // Both versions when a pin is set, each marked with where it came from. A header that
            // showed only the real one would hide that the project reasons from a different number
            // everywhere else, and one that showed only the pin would describe a server this report
            // is not about.
            serverVersions: $target instanceof InstanceTarget
                ? $this->reportedVersions($target, $serverVersion, $this->config->get('sqlens.assume_server_version'))
                : [],
            toolVersions: [],
            // Static: an audit reads a catalog and captures no migration, so neither capture mode
            // describes it. Saying "pretend" would claim a migration was simulated.
            mode: ReportingCaptureMode::Static,
            profile: RunProfile::tryFrom(is_string($profile) ? $profile : 'local') ?? RunProfile::Local,
            // The per-run override, resolved against the configured value. The audit used to read
            // the config directly here, so `--strict-tools` on a security run reached the lint half and
            // stopped at this line — one half strict, the other not, from a single flag.
            strictTools: $overrides->strictTools($this->config->get('sqlens.strict_tools') === true),
            strictUndetermined: $overrides->strictUndetermined($this->config->get('sqlens.strict_undetermined') === true),
            roundtrip: false,
            sqlensVersion: PackageVersion::current(),
            level: $level,
            // The security severity floor, which this suite used to drop on the floor. It travels
            // into the lint suite through ConfigRunContextCollector; the audit builds its context by
            // hand and simply never passed it, so the gate was permanently off here whatever the
            // config or an active profile said.
            //
            // The gate not firing was only half the harm. The header PRINTS this value, so every
            // audit report stated `min-severity=off` as a fact, and the same wrong value went into
            // the JSON envelope — public API under schema_version 2. A run that reports a setting it
            // does not honor is this package's own silent green, in the one place it advertises the
            // opposite.
            //
            // tryFrom, not from: an unrecognized value must not throw mid-run. The config validator
            // owns malformed input loudly and separately, so this path stays lenient and a bad key
            // can never turn a report into a crash.
            minSeverity: is_string($floor = $this->config->get('sqlens.security.min_severity'))
                ? Severity::tryFrom($floor)
                : null,
            activeRuleCount: $activeRules,
            // How many audit rules this run did NOT apply. The audit never passed this at all, so
            // every report it has ever produced said `hidden-rules=0` — while the level, the
            // category scope, the stability tier and the server's version between them routinely
            // withhold most of the set. `active-rules=7 hidden-rules=0` reads as "seven rules, that
            // is all there is", and a reader deciding whether a clean report means anything got a
            // zero that was not information but its absence.
            //
            // Same arithmetic as the lint suite — registered minus active — so the two headers
            // cannot come to mean different things.
            hiddenRuleCount: $hiddenRules,
            // The second filter axis, stated for the same reason as the level beside it. A run
            // narrowed to one category checks a fraction of what an unnarrowed one does, and until
            // this line existed every audit header said `categories=all` — so the shorter report was
            // indistinguishable from a complete one, whether the scope came from the flag or, as of
            // now, from `sqlens.categories`.
            activeCategories: $activeCategories,
            instance: $target instanceof InstanceTarget ? $this->reportedInstance($target) : null,
            skips: $skips,
            tenant: is_string($tenant = $this->config->get('sqlens.audit.tenancy.reference')) && trim($tenant) !== ''
                ? $tenant
                : null,
            // WHICH rules got a subject, beside the count of the ones that were selected. The count
            // is fixed before anything is read and cannot tell a run over a full catalog from one
            // whose reader came back empty; the set can. Null on the refusal paths, which never
            // reached a dispatch at all — an empty list there would claim a run that evaluated
            // nothing, which is a different and much louder statement than "there was no run".
            evaluatedRuleIds: $evaluatedRuleIds,
            guardProfile: ConfigRunContextCollector::guardProfileFrom($this->config),
        );
    }

    /**
     * The versions a header states: what the server IS, and what the project assumed.
     *
     * Both, when a pin is set. The audit gates its rules on the real version — it is talking to the
     * machine these findings will be applied to — so a header showing only the pin would describe a
     * server this report is not about, and one showing only the real version would hide that every
     * lint run on the same project reasons from a different number.
     *
     * @return list<ReportedServerVersion>
     */
    private function reportedVersions(InstanceTarget $target, ?string $detected, mixed $pinned): array
    {
        $versions = $detected === null ? [] : [
            new ReportedServerVersion($target->connection, $detected, VersionSource::Detected),
        ];

        if (is_string($pinned) && $pinned !== '') {
            // Stated even when it agrees with the server. "the pin matches" and "there is no pin"
            // are different facts about a project, and only one of them was somebody's decision.
            $versions[] = new ReportedServerVersion($target->connection, $pinned, VersionSource::Assumed);
        }

        return $versions;
    }

    /**
     * The audit's own instance resolution, flattened into the shape a report prints.
     *
     * Projected rather than handed over whole: {@see InstanceTarget} carries the comparison logic
     * between configured intent and observed reality, and the reporting layer — which the lint
     * suite also uses — has no business depending on the audit suite to render a header.
     */
    private function reportedInstance(InstanceTarget $target): ReportedInstance
    {
        $identity = $target->identity;

        return new ReportedInstance(
            connection: $target->connection,
            driver: $target->driver,
            // The observed host wins over the configured one, and falls back to the pin rather
            // than to the config: the pin is what this run asked for, while the config may name a
            // list the framework chose from at random.
            // `->` rather than `?->` on the left of `??`, which looks unsafe and is not: `??`
            // uses isset semantics, so a property read on null yields the right-hand side instead
            // of erroring. PHPStan enforces the shorter form; the note is here so the next reader
            // does not "fix" it back.
            host: $identity->host ?? $target->pinnedHost,
            port: $identity->port ?? $target->configuredPort,
            database: $identity->database ?? $target->configuredDatabase,
            role: $target->role()->value,
            roleReason: InstanceRole::undeterminedBecause($identity)?->value,
            pinVerdict: $target->pinVerdict()->value,
            poolerVerdict: $target->pooler?->verdict->value,
        );
    }

    private function metadata(RunOverrides $overrides): RunMetadata
    {
        $profile = $this->config->get('sqlens.profile');

        return new RunMetadata(
            serverVersions: [],
            toolVersions: [],
            mode: CaptureMode::Pretend,
            profile: is_string($profile) ? $profile : 'local',
            // The per-run override, resolved against the configured value. The audit used to read
            // the config directly here, so `--strict-tools` on a security run reached the lint half and
            // stopped at this line — one half strict, the other not, from a single flag.
            strictTools: $overrides->strictTools($this->config->get('sqlens.strict_tools') === true),
        );
    }
}
