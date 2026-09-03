<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Capture\PreScan\Catalog\CatalogEntry;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalog;
use Pushery\SQLens\Capture\PreScan\Catalog\PreScanCatalogs;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreScanDetector;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\VersionWindow;

/**
 * Finds the most common shape of the pretend trap: a migration whose DDL sits
 * behind a schema-introspection guard.
 *
 *     if (! Schema::hasColumn('users', 'slug')) {
 *         Schema::table('users', fn (Blueprint $t) => $t->string('slug'));
 *     }
 *
 * Measured against the installed framework, this is worse than "reads return
 * nothing" — it is a DOUBLE trap:
 *
 *   1. `Schema::hasColumn()` returns FALSE under pretend for a column that
 *      really exists, so the guard runs its else branch — or nothing at all.
 *      The `alter table` is never emitted.
 *   2. The introspection SELECT itself IS written to the pretend log. So the
 *      statement list is NON-EMPTY yet contains none of the migration's real
 *      DDL.
 *
 * A capture that trusted either half would report a clean pass over work it
 * never saw — the prototype of a silent green. That is why this is caught by the
 * static pre-scan up front rather than judged from the pretend result afterwards:
 * by the time the empty result exists, the damage (a plausible-looking pass) is
 * already done. The migration is `undetermined`, and shadow mode — which runs
 * against a throwaway database and gets a real answer — is named as the way out.
 *
 * **A guard is good practice, not a mistake, and the finding says so.** Writing
 * `if (! Schema::hasColumn(...))` is exactly how a re-runnable migration should
 * be written; the problem is not the guard but that pretend cannot see through
 * it. The remedy is a shadow run or, if the guard is not needed, removing it —
 * never "stop guarding your migrations".
 */
final readonly class SchemaIntrospectionGuardDetector implements PreScanDetector
{
    public const string RULE_ID = 'CAP.PRESCAN.INTROSPECTION_GUARD';

    private PreScanCatalog $catalog;

    public function __construct(?PreScanCatalogs $catalogs = null)
    {
        $this->catalog = ($catalogs ?? PreScanCatalogs::bundled())->catalog(PreScanCatalogs::INTROSPECTION_GUARDS);
    }

    public function metadata(): CaptureRuleMetadata
    {
        return new CaptureRuleMetadata(
            id: self::RULE_ID,
            category: Category::Safety,
            level: Level::Capturable,
            severity: null,
            // Stable: the trap is a measured framework behavior, not a heuristic
            // over an application's own code. The set of introspection methods is
            // finite and known, so the false-positive rate is a property of the
            // list rather than something a corpus has to establish.
            stability: StabilityTier::Stable,
            deprecation: null,
            versionWindow: VersionWindow::unbounded(),
            downtimeClass: null,
            downtimeClassRationale: 'A pre-scan hit describes no DDL — it is the reason a migration was not captured at all — so it has no downtime behavior to classify.',
            messagePrefix: 'Schema introspection guard',
            documentationUrl: RuleDocumentationUrl::for(self::RULE_ID),
            suites: PreScanMetadataAudit::defaultSuites(),
            badExample: <<<'PHP'
                public function up(): void
                {
                    // Under pretend hasColumn() is always false, so the alter is never
                    // captured — the run reports a clean pass over DDL it never saw.
                    if (! Schema::hasColumn('users', 'slug')) {
                        Schema::table('users', function (Blueprint $table): void {
                            $table->string('slug')->nullable();
                        });
                    }
                }
                PHP,
            goodExample: <<<'PHP'
                // The guard is good practice — keep it. Capture this migration in shadow
                // mode instead, which runs against a throwaway database and gets a real
                // answer from hasColumn(), so the alter inside the guard is seen.
                //
                //     php artisan sqlens:lint --shadow
                //
                // Removing the guard is the other option, only where re-runnability was
                // not actually needed.
                PHP,
        );
    }

    public function detect(ScannedMigration $migration): array
    {
        $hits = [];
        $seenLines = [];

        foreach ($migration->migrationCalls() as $call) {
            // Only a guard steers control flow. A bare `Schema::hasTable(...)`
            // whose result is thrown away is not a guard and hides no DDL — the
            // trap is specifically that a BRANCH is decided on the empty answer.
            if (! $call['context']->insideCondition) {
                continue;
            }

            $entry = $this->catalog->match($call['target']);
            if (! $entry instanceof CatalogEntry) {
                continue;
            }
            if (in_array($call['line'], $seenLines, true)) {
                continue;
            }

            $hits[] = $this->hit($migration->file, $call, $entry);
            $seenLines[] = $call['line'];
        }

        return $hits;
    }

    /**
     * @param  array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}  $call
     */
    private function hit(string $file, array $call, CatalogEntry $entry): PreScanHit
    {
        return new PreScanHit(
            self::RULE_ID,
            $file,
            $call['line'],
            sprintf(
                'The guard at line %d %s. The guard is good practice — the problem is that pretend mode cannot see past it. Capture this migration in shadow mode, which runs against a throwaway database and gets a real answer; or remove the guard if its re-runnability was not needed.',
                $call['line'],
                $entry->reason,
            ),
            $call['target']->description,
        );
    }
}
