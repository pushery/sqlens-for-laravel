<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use LogicException;
use Pushery\SQLens\Analyse\AnalyseRuleCatalog;
use Pushery\SQLens\Analyse\AnalyseRuleMetadata;
use Pushery\SQLens\Audit\AuditNotice;
use Pushery\SQLens\Capture\CaptureFindingCatalog;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Catalog\Degradation\CatalogNotice;
use Pushery\SQLens\Catalog\Security\SecurityNotice;
use Pushery\SQLens\Contracts\Attribution;
use Pushery\SQLens\Contracts\DerivesDowntimeClass;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Contracts\RunNotice;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;
use Pushery\SQLens\Deploy\DebtNotice;
use Pushery\SQLens\Deploy\DeployCheckCatalog;
use Pushery\SQLens\Deploy\DeployCheckMetadata;
use Pushery\SQLens\Drivers\DriverRegistry;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Lint\RunnerNotice;
use Pushery\SQLens\Rules\DocumentationPageIndex;
use Pushery\SQLens\Rules\RuleDocumentationState;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\Suite;

/**
 * Everything this package can report, as one deterministically sorted machine-readable artifact.
 *
 * Three families produce findings, and until now nothing could see all three at once: the engine
 * rule sets reachable through the drivers, the capture layer's level-0 rules and pre-scan
 * detectors, and the runner's own notices. Each carries an id, a documentation URL and the
 * metadata a report shows — but they carry it through three different shapes, so "does every
 * finding this package can emit have a documentation page?" was a question nobody could ask
 * mechanically. This is the answer surface: one row per documented id, one fixed key order, one
 * sort.
 *
 * ## What it is FOR
 *
 * - The documentation generator reads it instead of discovering rules on its own, so it fills
 *   pages rather than inventing addresses.
 * - The completeness check counts {@see RuleDocumentationState::Pending} rows. A page that has
 *   not been written is a NAMED state here, never an absence — the same reason a finding that
 *   could not be determined says so instead of passing.
 * - It ships, so a consuming application (or an agent working inside one) can read the rule
 *   catalog out of `vendor/` without booting a driver, a connection or a config.
 *
 * ## Determinism
 *
 * Rows are sorted by id and every row has the same keys in the same order, so two runs over an
 * unchanged tree produce byte-identical JSON and a real change shows up as a readable diff. The
 * export takes no timestamps and no environment: the only inputs are the registered producers
 * and the set of pages that exist.
 *
 * A rule's metadata does not depend on the project root it was built for — the root only shapes a
 * finding's location — so the export is stable across machines as well as across runs.
 */
final readonly class RuleRegistryExport
{
    /**
     * The artifact's shape version. A reader that understands version 1 may refuse a 2 it does
     * not know rather than silently misreading it.
     */
    public const int SCHEMA_VERSION = 1;

    /** Where the generated artifact lives, relative to the package root. */
    public const string BUNDLED_FILE = 'resources/data/rule-registry.json';

    /** The three families a row can come from — stated per row, so a reader can filter. */
    public const string SOURCE_RULE = 'rule';

    public const string SOURCE_CAPTURE = 'capture';

    public const string SOURCE_RUNNER = 'runner';

    /**
     * A rule that judges PHP SOURCE rather than a statement — the analyse suite's PHPStan rules.
     *
     * The fourth family, and it was added the hard way: its first rule shipped, reported, and
     * appeared in no catalog at all. Its id was therefore never put through the format contract
     * either, and it did not match — a malformed id in a working rule, with nothing red anywhere,
     * because the guard that refuses malformed ids can only see ids the registry carries.
     */
    public const string SOURCE_ANALYSE = 'analyse';

    /**
     * A check the deploy gate asks the target database, before or after the migration.
     *
     * The fifth family, and it arrived the same way the fourth did: twelve ids EMITTED a
     * documentation URL from `RuleDocumentationUrl::for()` and reached no catalog, so every one of
     * them shipped a link to a page nobody had written — and a baseline naming one was rejected as
     * an unknown id.
     */
    public const string SOURCE_DEPLOY = 'deploy';

    /**
     * The whole shipped surface: every driver's rules, the capture catalog, the runner notices.
     *
     * The drivers arrive through the registry rather than as concrete classes, so this stays the
     * driver-neutral core and a later engine is included by being registered — not by being
     * remembered here.
     *
     * @return array{schema_version: int, documentation_base: string, counts: array{total: int, published: int, pending: int}, entries: list<array<string, mixed>>}
     */
    public static function shipped(DriverRegistry $drivers, DocumentationPageIndex $pages): array
    {
        $rules = [];

        foreach ($drivers->all() as $driver) {
            foreach ($driver->rules() as $rule) {
                $rules[] = $rule;
            }
        }

        // ALL FOUR notice families, never a subset: a family the export cannot see is a family of
        // ids with no documentation page and nothing to notice the gap. The audit's own eighteen
        // were exactly that — written as literals, in no registry, each shipping a dead link.
        return self::build(
            $rules,
            CaptureFindingCatalog::metadata(),
            [...RunnerNotice::cases(), ...CatalogNotice::cases(), ...AuditNotice::cases(), ...DebtNotice::cases(), ...SecurityNotice::cases()],
            $pages,
            AnalyseRuleCatalog::metadata(),
            DeployCheckCatalog::metadata(),
        );
    }

    /**
     * The export over an explicit set of producers — what a test pins behavior with, and what a
     * generator uses when it composes the set itself.
     *
     * @param  list<Rule>  $rules
     * @param  list<CaptureRuleMetadata>  $captureMetadata
     * @param  list<RunNotice>  $notices
     * @param  list<AnalyseRuleMetadata>  $analyseMetadata
     * @param  list<DeployCheckMetadata>  $deployMetadata
     * @return array{schema_version: int, documentation_base: string, counts: array{total: int, published: int, pending: int}, entries: list<array<string, mixed>>}
     */
    public static function build(array $rules, array $captureMetadata, array $notices, DocumentationPageIndex $pages, array $analyseMetadata = [], array $deployMetadata = []): array
    {
        /** @var array<string, array<string, mixed>> $entries */
        $entries = [];

        foreach ($rules as $rule) {
            self::put($entries, self::fromRule($rule, $pages));
        }

        foreach ($captureMetadata as $metadata) {
            self::put($entries, self::fromCaptureMetadata($metadata, $pages));
        }

        foreach ($notices as $notice) {
            self::put($entries, self::fromRunNotice($notice, $pages));
        }

        foreach ($analyseMetadata as $metadata) {
            self::put($entries, self::fromAnalyseMetadata($metadata, $pages));
        }

        foreach ($deployMetadata as $metadata) {
            self::put($entries, self::fromDeployMetadata($metadata, $pages));
        }

        ksort($entries, SORT_STRING);

        $rows = array_values($entries);

        $published = count(array_filter(
            $rows,
            static fn (array $row): bool => $row['documentation_state'] === RuleDocumentationState::Published->value,
        ));

        return [
            'schema_version' => self::SCHEMA_VERSION,
            'documentation_base' => RuleDocumentationUrl::BASE,
            'counts' => [
                'total' => count($rows),
                'published' => $published,
                'pending' => count($rows) - $published,
            ],
            'entries' => $rows,
        ];
    }

    /**
     * The artifact as the bytes that belong in the repo: pretty-printed so a diff is readable,
     * slashes and unicode left alone so a URL reads as a URL, and newline-terminated like every
     * other text file in the tree.
     *
     * @param  array<string, mixed>  $export
     */
    public static function encode(array $export): string
    {
        return json_encode(
            $export,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        )."\n";
    }

    /**
     * Add a row, refusing a second row for an id that already has one UNLESS the two agree.
     *
     * Two drivers legitimately register the same driver-neutral lifecycle rule, so a duplicate id
     * is normal and first-wins is correct — as long as the rows are identical. If they are not,
     * one id describes two different things and the export would silently publish whichever came
     * first, which is exactly the kind of quiet wrong answer this package refuses.
     *
     * @param  array<string, array<string, mixed>>  $entries
     * @param  array<string, mixed>  $row
     */
    private static function put(array &$entries, array $row): void
    {
        /** @var string $id */
        $id = $row['id'];
        $existing = $entries[$id] ?? null;

        if ($existing !== null && $existing !== $row) {
            throw new LogicException(sprintf(
                'Two producers claim the rule id "%s" with different metadata; one id cannot describe two findings.',
                $id,
            ));
        }

        $entries[$id] = $row;
    }

    /**
     * The fixed row shape, filled from whatever the source could answer.
     *
     * Every row has every key, including the ones a given family has no value for. A uniform
     * shape is what lets a consumer read the artifact without branching per source, and it keeps
     * the diff of a real change small — a missing key would move every line after it.
     *
     * @param  list<string>  $suites
     * @return array<string, mixed>
     */
    private static function row(
        string $id,
        string $source,
        bool $coversFamily,
        DocumentationPageIndex $pages,
        string $category,
        int $level,
        ?string $severity,
        string $stability,
        ?string $confidence,
        ?string $deprecatedSince,
        ?string $replacedBy,
        ?string $minVersion,
        ?string $maxVersion,
        ?string $downtimeClass,
        string $messagePrefix,
        array $suites,
        Attribution $attribution,
        ?string $documentationUrl = null,
        bool $downtimeClassDerived = false,
        ?string $debtKind = null,
        bool $severityDerived = false,
        ?string $reportedIdentifier = null,
    ): array {
        return [
            'id' => $id,
            'slug' => RuleDocumentationUrl::slug($id),
            'source' => $source,
            'covers' => $coversFamily ? 'family' : 'exact',
            // Whether this id names something the READER wrote or something the run OBSERVED, which
            // is the field that decides whether it owes a bad/good example pair. `source` almost
            // answers it and not quite: the deploy family splits down the middle, and no shipped
            // field separated the halves — `severity` is null for a lock blocker and for an unread
            // statistic alike. {@see Attribution} carries the criterion.
            'attribution' => $attribution->value,
            // The two texts a consumer needs to READ a rule rather than only classify it. They are
            // derived from the documentation page's front matter, never authored here: the page is
            // already the one statement of what a rule is, and a second copy would be a second
            // thing to keep in step.
            //
            // An empty string means the page does not exist yet, which `documentation_state`
            // reports as `pending` on the same row. Nothing is invented to fill the gap — a
            // catalog that made up a title would look complete and say the wrong thing.
            //
            // `rationale` is deliberately NOT here. The page BODY is the rationale; it is long, it
            // has no second source to derive from, and every row already carries the stable
            // `documentation_url` that reaches it.
            'title' => $pages->titleFor($id),
            'summary' => $pages->summaryFor($id),
            'documentation_url' => $documentationUrl ?? RuleDocumentationUrl::for($id),
            'documentation_state' => $pages->stateFor($id)->value,
            'category' => $category,
            'level' => $level,
            'severity' => $severity,
            // The same two-absences problem `downtime_class_derived` solves, one field over. A null
            // `severity` with this false means the finding carries none at all; with it TRUE the
            // severity exists and is decided per finding, so naming one here would contradict the
            // findings themselves. A consumer reading only `severity` is still correct.
            'severity_derived' => $severityDerived,
            'stability' => $stability,
            'confidence' => $confidence,
            'deprecated_since' => $deprecatedSince,
            // The successor, where one exists. Carried because a deprecated id is never recycled
            // and never deleted: findings from older releases keep naming it, and a reader who
            // looks it up in this catalog is asking exactly one question — what answers this now.
            // The model has recorded it since deprecation existed; without this line it reached
            // nobody outside the source.
            'replaced_by' => $replacedBy,
            'min_version' => $minVersion,
            'max_version' => $maxVersion,
            'downtime_class' => $downtimeClass,
            // Two different absences the field alone cannot tell apart. A null `downtime_class`
            // with this false means the rule classifies no downtime at all; with it TRUE the class
            // exists but is decided per statement, so the catalog would be lying to name one here.
            // A consumer reading only the enum field is still correct — it never has to know.
            'downtime_class_derived' => $downtimeClassDerived,
            'message_prefix' => $messagePrefix,
            // The identifier the TOOL reports under, where that differs from the rule id. Null for
            // every family whose finding carries the rule id itself — there is nothing to bridge.
            //
            // The analyse suite is the exception and the reason this field exists: PHPStan owns the
            // identifier namespace of its own output, so `--error-format=json` hands a consumer
            // `sqlens.rawSql.interpolation` and never `SEC.INJ.RAW_INTERPOLATION`. Without this
            // column that consumer cannot join its findings to anything in here — not the severity,
            // not the category, not the level — and would have to hard-code a mapping this package
            // never published.
            'reported_identifier' => $reportedIdentifier,
            // What KIND of lasting debt this rule's findings describe, or null for the rules that
            // describe none — which is almost all of them. It is here because the catalog is what a
            // consumer reads to learn what this build can produce, and a debt kind that existed
            // only in the source would leave the agent layer and the rule docs unable to name the
            // account's own vocabulary.
            'debt_kind' => $debtKind,
            'suites' => $suites,
        ];
    }

    /** @return array<string, mixed> */
    private static function fromRule(Rule $rule, DocumentationPageIndex $pages): array
    {
        $window = $rule->versionWindow();
        $downtime = $rule->downtimeClass();

        return self::row(
            id: $rule->id(),
            source: self::SOURCE_RULE,
            coversFamily: false,
            pages: $pages,
            category: $rule->category()->value,
            level: $rule->level()->value,
            severity: $rule->severity()?->value,
            stability: $rule->stability()->value,
            confidence: $rule->confidence()->value,
            deprecatedSince: $rule->deprecation()?->since,
            replacedBy: $rule->deprecation()?->replacedBy,
            minVersion: $window->minVersion?->toString(),
            maxVersion: $window->maxVersion?->toString(),
            downtimeClass: $downtime instanceof DowntimeClass ? $downtime->value : null,
            messagePrefix: $rule->messagePrefix(),
            suites: array_map(static fn (Suite $suite): string => $suite->value, $rule->suites()),
            // A rule judges a statement the reader wrote, so the classification is a property of
            // the family rather than of the entry: there is no engine rule that reports on the run.
            attribution: Attribution::Authored,
            documentationUrl: $rule->documentationUrl(),
            downtimeClassDerived: $rule instanceof DerivesDowntimeClass,
            debtKind: $rule instanceof ProducesDebt ? $rule->debtKind() : null,
        );
    }

    /** @return array<string, mixed> */
    private static function fromCaptureMetadata(CaptureRuleMetadata $metadata, DocumentationPageIndex $pages): array
    {
        return self::row(
            id: $metadata->id,
            source: self::SOURCE_CAPTURE,
            coversFamily: false,
            pages: $pages,
            category: $metadata->category->value,
            level: $metadata->level->value,
            severity: $metadata->severity?->value,
            stability: $metadata->stability->value,
            // The capture producers declare no confidence: their verdicts are statements about
            // what the capture DID, not judgments that could be more or less certain.
            confidence: null,
            deprecatedSince: $metadata->deprecation?->since,
            replacedBy: $metadata->deprecation?->replacedBy,
            minVersion: $metadata->versionWindow->minVersion?->toString(),
            maxVersion: $metadata->versionWindow->maxVersion?->toString(),
            downtimeClass: $metadata->downtimeClass?->value,
            messagePrefix: $metadata->messagePrefix,
            suites: array_map(static fn (Suite $suite): string => $suite->value, $metadata->suites),
            // Read out rather than restated: the metadata's constructor takes the two examples as
            // REQUIRED arguments, so a capture id that reported on the run could not be declared.
            attribution: $metadata->attribution(),
            documentationUrl: $metadata->documentationUrl,
        );
    }

    /** @return array<string, mixed> */
    private static function fromDeployMetadata(DeployCheckMetadata $metadata, DocumentationPageIndex $pages): array
    {
        return self::row(
            id: $metadata->id,
            source: self::SOURCE_DEPLOY,
            coversFamily: false,
            pages: $pages,
            category: $metadata->category->value,
            level: $metadata->level->value,
            severity: $metadata->severity?->value,
            stability: $metadata->stability->value,
            // No confidence here even though some checks carry one per finding: a heuristic estimate
            // and a catalog fact can come from the SAME check depending on what it could read, so a
            // single value would be wrong for half the findings it describes.
            confidence: null,
            deprecatedSince: null,
            replacedBy: null,
            // No version window: these run against whatever the target is, and the check itself
            // decides whether it applies to that engine.
            minVersion: null,
            maxVersion: null,
            // Eight of the twelve DO classify one, and the first version of this method wrote null
            // for all of them — which the row states as "classifies no downtime whatsoever" while
            // the finding beside it said `blocking`. The class is declared with the check now.
            downtimeClass: $metadata->downtimeClass?->value,
            messagePrefix: $metadata->messagePrefix,
            suites: array_map(static fn (Suite $suite): string => $suite->value, $metadata->suites),
            // The only family that splits, and the only one where this is a per-entry decision.
            attribution: $metadata->attribution,
            documentationUrl: $metadata->documentationUrl(),
            downtimeClassDerived: $metadata->downtimeClassDerived,
            severityDerived: $metadata->severityDerived,
        );
    }

    /** @return array<string, mixed> */
    private static function fromAnalyseMetadata(AnalyseRuleMetadata $metadata, DocumentationPageIndex $pages): array
    {
        return self::row(
            id: $metadata->id,
            source: self::SOURCE_ANALYSE,
            coversFamily: false,
            pages: $pages,
            category: $metadata->category->value,
            level: $metadata->level->value,
            severity: $metadata->severity->value,
            stability: $metadata->stability->value,
            // No confidence, and not because nobody filled it in. Confidence rates how sure a rule
            // is about a JUDGMENT it made; this family answers "is a reason written down", which is
            // either true or false at the call site. A confidence on it would be decoration.
            confidence: null,
            deprecatedSince: null,
            replacedBy: null,
            // No version window: these rules read PHP source, so no server version can change their
            // answer. Unbounded is the honest value rather than an omission.
            minVersion: null,
            maxVersion: null,
            // And no downtime class: a call site is not a DDL statement, so there is no locking
            // behavior to classify.
            downtimeClass: null,
            messagePrefix: $metadata->messagePrefix,
            suites: array_map(static fn (Suite $suite): string => $suite->value, $metadata->suites),
            // A PHPStan rule over the reader's own PHP source — authored by construction.
            attribution: Attribution::Authored,
            documentationUrl: $metadata->documentationUrl(),
            reportedIdentifier: $metadata->reportedIdentifier,
        );
    }

    /** @return array<string, mixed> */
    private static function fromRunNotice(RunNotice $notice, DocumentationPageIndex $pages): array
    {
        return self::row(
            id: $notice->id(),
            source: self::SOURCE_RUNNER,
            coversFamily: $notice->coversFamily(),
            pages: $pages,
            category: $notice->category()->value,
            level: $notice->level()->value,
            // ⚠️ THIS USED TO STAMP `null` UNDER A COMMENT SAYING RUNNER NOTICES ARE NEVER
            // SEVERITY-GATED, AND ONE OF THEM ALWAYS WAS. `DEBT.UNRECORDED` ships with
            // `Severity::Info`, so the published artifact told a consumer the rule has no severity
            // while the finding it would receive carried one — and the severity is where
            // `DebtThresholds::escalate()` starts ageing a debt toward `high`. Asked now, so the
            // artifact reports what the notice really carries.
            //
            // The rest of the sentence still holds: a run notice carries no version window, is
            // never deprecated and classifies no downtime, because it describes the run rather
            // than a statement.
            severity: $notice->severity()?->value,
            stability: $notice->stability()->value,
            confidence: null,
            deprecatedSince: null,
            replacedBy: null,
            minVersion: null,
            maxVersion: null,
            downtimeClass: null,
            messagePrefix: $notice->messagePrefix(),
            suites: array_map(static fn (Suite $suite): string => $suite->value, $notice->suites()),
            // Always `Observed`, through the trait every notice family uses. The slot is asked for
            // anyway: a family that answered by not being asked would be the one place this
            // classification means nothing.
            attribution: $notice->attribution(),
            documentationUrl: $notice->documentationUrl(),
        );
    }
}
