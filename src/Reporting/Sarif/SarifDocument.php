<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Sarif;

use Pushery\SQLens\Deploy\DebtContext;
use Pushery\SQLens\Docs\DocumentationSite;
use Pushery\SQLens\Exceptions\UnreadableSarifSchema;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Generation\ShippedRuleMetadata;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Reporting\Agent\MarkdownText;
use Pushery\SQLens\Reporting\Baseline\FindingFingerprint;
use Pushery\SQLens\Reporting\RuleLimitations;
use Pushery\SQLens\Reporting\RunContext;
use Pushery\SQLens\Severity\GateDecision;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Severity\SeverityGate;

/**
 * One SARIF 2.1.0 log, built from the same `Result` and `RunContext` every other reporter reads.
 *
 * SARIF is the format a foreign pipeline understands: uploaded to GitHub, findings appear in the
 * code-scanning tab with their own history instead of scrolling past in a job log. That history is
 * the whole reason the shape below is careful — GitHub matches an alert across runs by its
 * fingerprint, so a document that is *correct* but not *stable* opens a fresh alert for the same
 * problem every night and teaches everybody to ignore the tab.
 *
 * ## What is deliberately not in here
 *
 * **No timestamp.** `invocation` may carry `startTimeUtc` and `endTimeUtc`, and both are omitted:
 * this package's determinism claim is that the same state serializes byte-identically, and a clock
 * reading breaks that for every consumer that diffs two reports. The run parameters that do vary
 * meaningfully — versions, mode, profile, the gate thresholds — are all in `invocation.properties`,
 * from the same {@see RunContext} the console header prints. One value type, two serializations.
 *
 * **`level` and `kind` from the outcome, the weight only on the risk axis.** {@see SeverityMapper} owns
 * the mapping: a pass or a structural not-applicable is `level: none` with the matching `kind`, an
 * undetermined is a `note`, and only a finding on the risk axis carries `security-severity`. Its rule is
 * tagged `security`, because GitHub weighs that property only on a rule with the tag. No finding is
 * dropped by any of it.
 *
 * **No invented location, and no missing one either.** A catalog or server finding has no file and no
 * line, and both obvious answers are wrong: an empty `locations` array validates and makes GitHub pin
 * the alert to the repository root, while a made-up file and line makes it look like a finding about
 * unrelated code. {@see LocationResolver} carries SARIF's own answer to that — the real subject as a
 * `logicalLocation`, an explicitly-named anchor file as the physical one — and the message says which
 * is which.
 *
 * ## Why `rules[]` holds only the rules that produced a result
 *
 * `tool.driver.rules` is a descriptor list, and a descriptor for a rule with no result says nothing
 * either way — it does not claim the rule ran, and a reader who took it that way would be wrong in
 * the direction this package cares about. The honest answer to "what ran" is the run's evaluated
 * set, which lives in the JSON report; SARIF's job here is to describe the findings it carries.
 */
final readonly class SarifDocument
{
    /** Where the SARIF version and its schema address live — a data artifact, never a literal here. */
    public const string BUNDLED_FILE = 'resources/data/sarif-schema.json';

    /**
     * The SARIF version and the schema document that defines it.
     *
     * Read from a bundled artifact rather than written into this class, and the reason is the same
     * one that puts every vendor documentation URL in `rule-evidence.json`: this package forbids a
     * foreign network endpoint inside shipped code, and a guard enforces it over `src/` and
     * `config/`. That guard is about hidden REACH, not about anchors — so an external address that
     * is declared, versioned and diffable belongs where a reviewer meets it. Nothing here ever
     * fetches the URL; it goes into the report's `$schema` key so a consumer's validator can resolve
     * it.
     *
     * The path is injectable so the refusal above can be driven with a broken artifact. A throw no
     * test can reach is a throw nobody has checked says what it means.
     *
     * @return array{version: string, schema: string}
     */
    public static function schema(?string $path = null): array
    {
        $raw = @file_get_contents($path ?? dirname(__DIR__, 3).'/'.self::BUNDLED_FILE);
        $decoded = $raw === false ? null : json_decode($raw, true);

        // No fallback to a hard-coded pair. A missing artifact is a broken installation, and a
        // document that quietly declared a version nobody shipped would be worse than one that says
        // it could not be built — the same rule this package applies to every other bundled read.
        if (! is_array($decoded) || ! is_string($decoded['sarif_version'] ?? null) || ! is_string($decoded['schema_url'] ?? null)) {
            throw UnreadableSarifSchema::at($path ?? self::BUNDLED_FILE);
        }

        return ['version' => $decoded['sarif_version'], 'schema' => $decoded['schema_url']];
    }

    /**
     * Where a reader is sent to learn what the tool is.
     *
     * Derived, never written out. This package has already shipped two addresses for one set of
     * pages because each link was typed where it was needed; the guard that caught that has been
     * pointed at every shipped file since, and it caught this one too.
     */
    public static function informationUri(): string
    {
        return DocumentationSite::page('');
    }

    private function __construct(
        private Result $result,
        private RunContext $context,
        private LocationResolver $locations,
    ) {}

    public static function for(Result $result, RunContext $context, ?LocationResolver $locations = null): self
    {
        return new self($result, $context, $locations ?? new LocationResolver);
    }

    /**
     * The document as a fixed-key-order array.
     *
     * @return array{version: string, '$schema': string, runs: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        // Sorted the way the console sorts, and for the same reason: two runs over one state must
        // produce one document, byte for byte. The rule id breaks ties inside one object so two
        // findings on one table cannot swap places between runs.
        $findings = $this->result->findings;
        usort($findings, static fn (Finding $a, Finding $b): int => [
            $a->location->sortKey(), $a->ruleId,
        ] <=> [
            $b->location->sortKey(), $b->ruleId,
        ]);

        $schema = self::schema();

        return [
            'version' => $schema['version'],
            '$schema' => $schema['schema'],
            'runs' => [[
                'tool' => [
                    'driver' => [
                        'name' => 'SQLens',
                        'informationUri' => self::informationUri(),
                        'version' => $this->context->sqlensVersion,
                        'rules' => $this->rules($findings, ShippedRuleMetadata::shipped(), RuleLimitations::shipped()),
                    ],
                ],
                // PLURAL, and an array. The spec's `run` object has `invocations`, and it sets
                // `additionalProperties: false` — so the singular key this file shipped with was not
                // a stylistic slip but a document every strict validator rejects. Caught by the
                // schema arm on its first run, which is the entire reason that arm
                // exists: the output had been eyeballed, and it looked right.
                'invocations' => [$this->invocation()],
                'results' => $this->results($findings),
            ]],
        ];
    }

    /**
     * One descriptor per rule that produced a result, sorted by id.
     *
     * `helpUri` is the finding's own documentation URL rather than a URL rebuilt from the id: the
     * rule already carries the stable one, and a second construction of the same address is a second
     * chance for the two to disagree — which shows up as a 404 in somebody's security tab.
     *
     * GitHub shows `fullDescription` and `help` beside every alert of the rule, so both come from the catalog that
     * ships: what the rule checks, and in the help what it does not check and where its page is. A rule the catalog
     * does not name on its own, a member of a family, falls back to its id, as the short description does.
     *
     * A descriptor is built from the LOUDEST finding of its rule. One rule can honestly report two loudnesses, a
     * privacy rule a strong signal as low and a weak one as info, and a descriptor taken from whichever finding sorted
     * last would let the names of two objects decide what the rule weighs. Among findings of equal weight the last
     * in sort order serves. Each result keeps its own severity.
     *
     * @param  list<Finding>  $findings
     * @param  array<string, array<array-key, mixed>>  $catalog
     * @return list<array<string, mixed>>
     */
    private function rules(array $findings, array $catalog, RuleLimitations $limitations): array
    {
        $loudest = [];

        foreach ($findings as $finding) {
            $kept = $loudest[$finding->ruleId] ?? null;

            if (! $kept instanceof Finding || ($finding->severity?->rank() ?? -1) >= ($kept->severity?->rank() ?? -1)) {
                $loudest[$finding->ruleId] = $finding;
            }
        }

        $rules = [];

        foreach ($loudest as $finding) {
            $rules[$finding->ruleId] = [
                'id' => $finding->ruleId,
                // The id doubles as the name. SARIF wants a human-readable one, and inventing a
                // prose title here would be a second naming of every rule that nothing keeps in
                // step with the documentation page.
                'name' => $finding->ruleId,
                'shortDescription' => ['text' => $finding->ruleId],
                'fullDescription' => ['text' => $this->summaryOf($catalog, $finding->ruleId) ?? $finding->ruleId],
                'helpUri' => $finding->documentationUrl,
                'help' => $this->help(
                    $this->summaryOf($catalog, $finding->ruleId) ?? $finding->ruleId,
                    $limitations->of($finding->ruleId) ?? [],
                    $finding->documentationUrl,
                ),
                'properties' => [
                    // GitHub filters alerts by tag. A rule on the risk axis is tagged `security` as well, the one tag
                    // under which GitHub reads `security-severity` below; without it the weight arrives and is ignored.
                    'tags' => $this->tags($finding),
                    'category' => $finding->category->value,
                    'level' => $finding->level->value,
                    'stability' => $finding->stability->value,
                    // Null for everything but a security or privacy finding, and stated rather than
                    // omitted: a consumer reading the key learns this rule is not weighed on the
                    // risk axis, where a missing key would only say the producer is older.
                    'severity' => $finding->severity?->value,
                    // …and the weight GitHub actually sorts by, on the RULE and not on the result.
                    // That is where its code-scanning ingestion reads it from, and a document that
                    // put it on the result instead would arrive with every alert unweighted while
                    // looking complete to a validator.
                    ...$this->securitySeverity($finding),
                ],
            ];
        }

        ksort($rules, SORT_STRING);

        return array_values($rules);
    }

    /**
     * What the catalog says the rule checks, or null where it does not name the rule on its own.
     *
     * @param  array<string, array<array-key, mixed>>  $catalog
     */
    private function summaryOf(array $catalog, string $ruleId): ?string
    {
        $summary = $catalog[$ruleId]['summary'] ?? null;

        return is_string($summary) && $summary !== '' ? $summary : null;
    }

    /**
     * The help of a rule, in the two forms SARIF has: what it checks, what it does not check, where its page is.
     *
     * @param  list<string>  $limitations
     * @return array{text: string, markdown: string}
     */
    private function help(string $summary, array $limitations, string $documentationUrl): array
    {
        $text = $summary;
        $markdown = MarkdownText::inline($summary);

        if ($limitations !== []) {
            $text .= "\n\nWhat this rule does not check:";
            $markdown .= "\n\n**What this rule does not check**\n";

            foreach ($limitations as $limitation) {
                $text .= "\n- ".$limitation;
                $markdown .= "\n- ".MarkdownText::inline($limitation);
            }
        }

        return [
            'text' => $text."\n\nDocumentation: ".$documentationUrl,
            'markdown' => $markdown."\n\n[Documentation](".$documentationUrl.')',
        ];
    }

    /**
     * The tags of a rule: its category, and `security` for a rule on the risk axis.
     *
     * @return list<string>
     */
    private function tags(Finding $finding): array
    {
        return array_values(array_unique([
            $finding->category->value,
            ...($finding->severity instanceof Severity ? ['security'] : []),
        ]));
    }

    /**
     * The single invocation, from the RunContext rather than reassembled here.
     *
     * Wrapped in an array by the caller: SARIF models a run as possibly several invocations — a tool
     * invoked once per target — and this package invokes itself once. One element is the honest
     * count, and the key is plural whatever that count is.
     *
     * The DoD this file was built against asks for exactly one thing to be impossible: a console
     * header and a SARIF `invocation` of the same run that disagree. Reading the same value type is
     * what makes it impossible, rather than a test that compares two independent constructions and
     * passes until somebody edits one of them.
     *
     * The properties are the whole run header, `instance` included: the host, port and database of
     * the audited server travel with the log wherever it is uploaded, as they do in the JSON report.
     * {@see RunContext} names the fields that vary between two runs.
     *
     * @return array<string, mixed>
     */
    private function invocation(): array
    {
        return [
            // Required by the spec. True means the tool ran to completion — which it did; whether it
            // FOUND anything is the results' business, and conflating the two would report a clean
            // database as a failed invocation.
            'executionSuccessful' => true,
            'properties' => $this->context->toArray(),
        ];
    }

    /**
     * One result per finding, each with its place among the findings that share its identity.
     *
     * Counted in the order the document lists them, which is the order the runners count in when they write the
     * baseline: the same statement twice in one migration is one fingerprint and two entries there, numbered from 0.
     *
     * @param  list<Finding>  $findings
     * @return list<array<string, mixed>>
     */
    private function results(array $findings): array
    {
        $occurrences = [];
        $results = [];

        foreach ($findings as $finding) {
            $fingerprint = FindingFingerprint::ofFinding($finding)->value;
            $occurrence = $occurrences[$fingerprint] ?? 0;
            $occurrences[$fingerprint] = $occurrence + 1;

            $results[] = $this->result($finding, $fingerprint, $occurrence);
        }

        return $results;
    }

    /**
     * One result per finding.
     *
     * @return array<string, mixed>
     */
    private function result(Finding $finding, string $fingerprint, int $occurrence): array
    {
        $result = [
            'ruleId' => $finding->ruleId,
            'level' => SeverityMapper::level($finding, $this->decision($finding)),
            ...SeverityMapper::kind($finding),
            'message' => ['text' => $this->locations->message($finding)],
            // Never empty, for any finding. A result SARIF would reject for want of a location is a
            // finding that vanished between the run and the report, and the count arm in
            // SarifLocationTest holds findings-in against results-out for exactly that.
            'locations' => $this->locations->locations($finding),
            // What lets GitHub recognize one problem across runs instead of opening a new alert
            // every night. The same fingerprint the baseline matches on, deliberately: a project
            // that has accepted a finding in its baseline and a security tab that keeps reopening it
            // would be two answers to one question.
            'partialFingerprints' => [
                'sqlensFindingFingerprint/v1' => $fingerprint,
                // The same finding twice, such as one statement written twice in a migration, shares that
                // fingerprint, and GitHub would read the two results as one. From the second occurrence on, the
                // number tells them apart, as the ordinal does in the baseline. The first carries none, so an
                // alert a previous upload opened keeps matching it.
                ...($occurrence > 0 ? ['sqlensOccurrence/v1' => (string) $occurrence] : []),
            ],
            'properties' => [
                'status' => $finding->status->outcome->value,
                // The three-valued result, kept three-valued inside a two-valued tool. An
                // undetermined is rendered as a `note` so a managed database does not turn every
                // upload into a wall of errors — and this key is what stops that from reading as
                // "checked, minor". A consumer can filter on exactly it.
                ...($finding->status->outcome === Outcome::Undetermined
                    ? [SeverityMapper::STATE => Outcome::Undetermined->value]
                    : []),
                // The named reason an undetermined carries, or null. This is the field that keeps a
                // check which could not run from reading like one that ran and found nothing.
                'undeterminedReason' => $finding->status->reason?->value,
                'notApplicableReason' => $finding->status->notApplicableReason?->value,
                'category' => $finding->category->value,
                'severity' => $finding->severity?->value,
                'downtimeClass' => $finding->downtimeClass?->value,
                // The reason a derived class could not be named, beside the key it stands in for.
                'downtimeUndeterminedReason' => $finding->downtimeUndetermined?->reason->value,
                'confidence' => $finding->confidence->value,
            ],
        ];

        if ($finding->debt instanceof DebtContext) {
            // The ledger's account, in the same selected-properties block as `severity` and
            // `downtimeClass` — not through the finding's own projection, which this reporter
            // deliberately does not reuse. A code-scanning alert for a debt that could not say how
            // long it had been open would reopen every night looking identical to the night before,
            // which is the one thing the fingerprint above exists to prevent.
            //
            // Spread from the same `toArray()` the JSON envelope reads, so the two surfaces cannot
            // grow different spellings of one account.
            $result['properties'] = [...$result['properties'], ...$finding->debt->toArray()];
        }

        $object = $finding->location->objectName;

        if ($object !== null) {
            // The subject a location cannot express. A catalog finding is about a table or a role,
            // not about a line of a file, and dropping the name would leave the alert saying only
            // which rule spoke.
            $result['properties']['object'] = $object;
        }

        // No `fixes` key here, on purpose, and this is the place somebody would add one.
        //
        // A finding may carry a full remediation payload, and SARIF has a `fixes` array made for
        // exactly that. Filling it is still refused, because of what the CONSUMER does with it:
        // GitHub renders a SARIF `fixes` entry as an APPLICABLE change, a button a reviewer presses
        // without reading the diff. That turns advice into an action at the exact moment nobody is
        // looking closely.
        //
        // The remediation schema is still `preview` and no consumer has ever seen a payload.
        // Offering an unproven schema as a one-click edit to a production migration is the wrong
        // order: the format has to earn trust before it earns a button.
        //
        // Where the material does go: the JSON envelope and `--format=agent` carry the payload in
        // full, for a reader who then decides. The refusal is about the applicable-change surface,
        // not about withholding the advice.
        //
        // Revisited when the schema is promoted `preview` → stable, and not before. That is the
        // trigger, not a date and not somebody's judgment that it looks ready.
        // `tests/Feature/Reporting/SarifCarriesNoFixesTest.php` holds this to it.

        return $result;
    }

    /**
     * This run's verdict on one finding — the same object the exit code and the summary counts read.
     *
     * Built here rather than passed in, and read rather than re-derived: whether a finding blocks is
     * a judgment about a RUN, so it needs the run's level and floor. Three readers computing it
     * separately is how a report starts disagreeing with the exit code printed beside it.
     */
    private function decision(Finding $finding): GateDecision
    {
        return GateDecision::for(
            $finding,
            Level::from($this->context->level),
            new SeverityGate($this->context->minSeverity),
        );
    }

    /**
     * The `security-severity` property, or nothing at all.
     *
     * Spread into the bag rather than set to null: SARIF's `properties` has no schema, so an
     * explicit null is a property whose value is null — and GitHub reads that as a weight it cannot
     * parse rather than as an absence. This is the one place in the package where absent and null
     * are not interchangeable, which is why it is its own method with this sentence on it.
     *
     * @return array<string, string>
     */
    private function securitySeverity(Finding $finding): array
    {
        $weight = SeverityMapper::securitySeverity($finding, $this->decision($finding));

        return $weight === null ? [] : [SeverityMapper::SECURITY_SEVERITY => $weight];
    }
}
