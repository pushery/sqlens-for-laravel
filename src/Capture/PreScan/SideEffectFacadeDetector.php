<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Capture\PreScan\Catalog\CatalogEntry;
use Pushery\SQLens\Capture\PreScan\Catalog\CatalogTarget;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalog;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalogs;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreScanDetector;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\VersionWindow;

/**
 * Finds migrations that would reach outside the database if they ran.
 *
 * Pretend mode intercepts SQL and nothing else. The PHP around the SQL executes
 * normally — so a `Notification::send()` in a migration sends a real
 * notification, an `Http::post()` calls a real endpoint, and a `dispatch()`
 * puts a real job on a real queue, all from a command whose entire promise is
 * that it looks at a migration WITHOUT running it. A lint run that mails a
 * customer is the worst thing this tool could do, so a migration touching any
 * cataloged surface is reported and never pretend-executed.
 *
 * The order matters: the pre-scan runs BEFORE the capture, because detecting a
 * side effect after it has fired is not a safety mechanism.
 *
 * **What the catalog deliberately does not carry.** `Log` is absent: writing a
 * log line is the one "side effect" a migration is expected to have, and
 * flagging it would make the rule fire on almost every real migration. The
 * distinction is not "does it do anything outside PHP" but "would a user regret
 * it having happened". A log line in a lint run is noise; a Slack message is an
 * incident.
 *
 * **What it cannot carry.** A hand-written list of names only ever catches known
 * mistakes. A side effect reached through the application's own code, or through
 * a call the scanner cannot resolve at all, is invisible here BY CONSTRUCTION,
 * which is why this catalog is never extended with project classes. A call it
 * cannot resolve is the dynamic-call detector's, which is stable. A call into the
 * application's own code is the indirect-call detector's, which is `preview`: a
 * run that does not admit that tier executes such a call in pretend mode, and the
 * configuration says so beside its allowlist.
 */
final readonly class SideEffectFacadeDetector implements PreScanDetector
{
    public const string RULE_ID = 'CAP.PRESCAN.SIDE_EFFECT';

    /** Where an application's own additions to the catalog are declared. */
    public const string CONFIG_PATH = 'sqlens.capture.prescan.side_effects.additional';

    private PreScanCatalog $catalog;

    /** @var list<CatalogTarget> */
    private array $additional;

    /**
     * @param  list<string>  $additional  extra targets from the host application's
     *                                    config, in the same written grammar as the
     *                                    bundled catalog
     */
    public function __construct(?PreScanCatalogs $catalogs = null, array $additional = [])
    {
        $this->catalog = ($catalogs ?? PreScanCatalogs::bundled())->catalog(PreScanCatalogs::SIDE_EFFECTS);

        $this->additional = array_map(
            // An application's entries reach here already validated by the config
            // validator, which reports a malformed one as a violation naming the
            // key. A malformed one that got this far is a bug in that path, so it
            // throws rather than being dropped: silently ignoring an entry a user
            // wrote would leave them believing a surface is watched when it is not.
            static fn (string $written): CatalogTarget => CatalogTarget::parse($written, self::CONFIG_PATH),
            $additional,
        );
    }

    public function metadata(): CaptureRuleMetadata
    {
        return new CaptureRuleMetadata(
            id: self::RULE_ID,
            category: Category::Safety,
            level: Level::Capturable,
            severity: null,
            // Stable, unlike the other pre-scan detectors: this catalog is a list
            // of named framework surfaces, not a heuristic, so its false-positive
            // rate is a property of the list rather than something a corpus has to
            // measure. An entry is either in it or it is not.
            stability: StabilityTier::Stable,
            deprecation: null,
            versionWindow: VersionWindow::unbounded(),
            downtimeClass: null,
            downtimeClassRationale: 'A pre-scan hit describes no DDL — it is the reason a migration was not captured at all — so it has no downtime behavior to classify.',
            messagePrefix: 'Side effect in migration',
            documentationUrl: RuleDocumentationUrl::for(self::RULE_ID),
            suites: PreScanMetadataAudit::defaultSuites(),
            badExample: <<<'PHP'
                public function up(): void
                {
                    Schema::table('users', function (Blueprint $table): void {
                        $table->string('plan')->default('free');
                    });

                    // A lint run would send this for real, to real people.
                    Notification::send(User::all(), new PlanChanged);
                }
                PHP,
            goodExample: <<<'PHP'
                public function up(): void
                {
                    Schema::table('users', function (Blueprint $table): void {
                        $table->string('plan')->default('free');
                    });
                }

                // The announcement is a deploy step, not a schema change. It runs when
                // the deploy says so, and a lint run cannot trigger it by looking.
                PHP,
        );
    }

    public function detect(ScannedMigration $migration): array
    {
        // One hit per line, and the one that names the surface. The calls of a chain arrive
        // outermost first, and an entry for a method on any receiver (`*::dispatch`) matches the
        // outer call of `app('events')->dispatch('x')` by its method name alone: read that way, an
        // event was reported as a job. So a named surface later on the same line replaces a
        // receiver-agnostic match, and nothing replaces a named one.
        /** @var array<int, array{entry: array{kind: string, reason: string, broad: bool}, target: CallTarget}> $matched */
        $matched = [];

        foreach ($migration->migrationCalls() as $call) {
            $entry = $this->match($call['target']);
            if ($entry === null) {
                continue;
            }

            $held = $matched[$call['line']] ?? null;
            if ($held !== null && (! $held['entry']['broad'] || $entry['broad'])) {
                continue;
            }

            $matched[$call['line']] = ['entry' => $entry, 'target' => $call['target']];
        }

        $hits = [];

        foreach ($matched as $line => $match) {
            $hits[] = new PreScanHit(
                self::RULE_ID,
                $migration->file,
                $line,
                sprintf(
                    'The call at line %d %s. Pretend mode intercepts SQL, not the PHP around it, so this would happen for real during a lint run. The migration is reported instead of being executed; move the effect into a deploy step or a job, or capture in shadow mode, which runs against a throwaway database.',
                    $line,
                    $match['entry']['reason'],
                ),
                $match['target']->description,
            );
        }

        return $hits;
    }

    /**
     * The bundled catalog first, then the application's own additions.
     *
     * `broad` marks an entry for a method on any receiver: it matched by the method's name, not
     * because the surface is known.
     *
     * @return array{kind: string, reason: string, broad: bool}|null
     */
    private function match(CallTarget $target): ?array
    {
        $entry = $this->catalog->match($target);

        if ($entry instanceof CatalogEntry) {
            return ['kind' => $entry->kind, 'reason' => $entry->reason, 'broad' => $entry->target->isReceiverAgnostic()];
        }

        foreach ($this->additional as $additional) {
            if ($additional->matches($target)) {
                return [
                    'kind' => 'configured',
                    'reason' => sprintf('reaches "%s", which this project declared a side-effect surface in its own configuration', $additional->raw),
                    'broad' => $additional->isReceiverAgnostic(),
                ];
            }
        }

        return null;
    }

    /**
     * Whether a written target is one this detector could accept — the predicate
     * the config validator asks before a run starts, so a typo in an
     * application's config is a named violation rather than an entry that
     * quietly watches nothing.
     */
    public static function acceptsTarget(string $written): bool
    {
        return CatalogTarget::tryParse($written) instanceof CatalogTarget;
    }

    /** How many surfaces this detector watches — bundled plus configured. */
    public function catalogSize(): int
    {
        return $this->catalog->count() + count($this->additional);
    }
}
