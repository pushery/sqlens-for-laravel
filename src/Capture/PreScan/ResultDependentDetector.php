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
 * Finds migrations whose SQL depends on what a query answers.
 *
 * Pretend mode does not execute; it logs. Every SELECT it intercepts comes back
 * empty, so a `chunk()` loop runs zero times, an `if ($query->exists())` takes
 * the other branch, and a backfill emits nothing at all. The capture would then
 * hold a strict SUBSET of the statements the real migration runs — and the run
 * would be green, because nothing failed. That is the exact shape of "silent
 * green" the package refuses, so a migration with this shape is `undetermined`
 * and the report points at the shadow mode, which executes for real against a
 * throwaway database and can answer.
 *
 * Three arms, each deliberately scoped:
 *
 * - **Materialization and iteration** fire wherever they appear in `up()`/`down()`.
 *   Reading rows in a migration means the migration is about those rows.
 * - **Predicates** (`count`, `exists`, `sum`, …) fire ONLY inside a condition.
 *   A count that is merely logged changes no SQL, and flagging it would make the
 *   detector noise — a rule that flags everything gets switched off, and then it
 *   protects nothing. That is the FP boundary, and it is drawn here on purpose.
 * - **DDL inside an unbounded loop** fires for a schema or data change emitted
 *   from a loop whose iteration count the scanner cannot see. A loop over a
 *   written-out array is excluded: it runs the same number of times with or
 *   without a database.
 */
final readonly class ResultDependentDetector implements PreScanDetector
{
    public const string RULE_ID = 'CAP.PRESCAN.RESULT_DEPENDENT';

    private PreScanCatalog $patterns;

    private PreScanCatalog $exemptions;

    private PreScanCatalog $ddlEmitters;

    public function __construct(?PreScanCatalogs $catalogs = null)
    {
        $source = $catalogs ?? PreScanCatalogs::bundled();

        $this->patterns = $source->catalog(PreScanCatalogs::RESULT_DEPENDENT);
        $this->exemptions = $source->catalog(PreScanCatalogs::RESULT_DEPENDENT_EXEMPT);
        $this->ddlEmitters = $source->catalog(PreScanCatalogs::DDL_EMITTERS);
    }

    public function metadata(): CaptureRuleMetadata
    {
        return new CaptureRuleMetadata(
            id: self::RULE_ID,
            category: Category::Safety,
            // Level 0 is the lint suite's lowest assurance — "the SQL is
            // capturable". A result-dependent migration is precisely the case
            // where it is not, so this sits at the bottom rather than nowhere.
            level: Level::Capturable,
            // No severity: this is a capture limitation, not a risk ranking, and
            // safety is not a severity-gated category.
            severity: null,
            // Preview until the false-positive rate is measured against a real
            // corpus rather than the synthetic one. The governance contract is
            // that new rules land as preview; this one has a specific reason too.
            stability: StabilityTier::Preview,
            deprecation: null,
            // Unbounded, and stated: the pre-scan reads PHP, never a server, so
            // no server version can change its answer.
            versionWindow: VersionWindow::unbounded(),
            downtimeClass: null,
            downtimeClassRationale: 'A pre-scan hit describes no DDL — it is the reason a migration was not captured at all — so it has no downtime behavior to classify.',
            messagePrefix: 'Result-dependent migration',
            documentationUrl: RuleDocumentationUrl::for(self::RULE_ID),
            suites: PreScanMetadataAudit::defaultSuites(),
            badExample: <<<'PHP'
                public function up(): void
                {
                    // Under pretend this loop runs zero times, so the UPDATE below
                    // is never captured and the run reports no findings at all.
                    DB::table('users')->whereNull('slug')->chunkById(500, function ($users): void {
                        foreach ($users as $user) {
                            DB::table('users')->where('id', $user->id)->update(['slug' => Str::slug($user->name)]);
                        }
                    });
                }
                PHP,
            goodExample: <<<'PHP'
                public function up(): void
                {
                    // The schema change is what the migration owns; the backfill is a
                    // job the deploy runs afterwards. The migration now captures whole.
                    Schema::table('users', function (Blueprint $table): void {
                        $table->string('slug')->nullable();
                    });

                    BackfillUserSlugs::dispatch();
                }
                PHP,
        );
    }

    public function detect(ScannedMigration $migration): array
    {
        $hits = [];
        $seenLines = [];

        foreach ($migration->migrationCalls() as $call) {
            $hit = $this->hitFor($migration->file, $call);
            if (! $hit instanceof PreScanHit) {
                continue;
            }
            if (in_array($hit->line, $seenLines, true)) {
                continue;
            }

            $hits[] = $hit;
            $seenLines[] = $hit->line;
        }

        return $hits;
    }

    /**
     * @param  array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}  $call
     */
    private function hitFor(string $file, array $call): ?PreScanHit
    {
        // The exemptions cover the METHOD-NAME collision only — `Config::get` is
        // not a query read. They deliberately do not reach the loop arm below:
        // `Schema::table` is exempt from being called a query read and is exactly
        // what the loop arm is looking for.
        $pattern = $this->exemptions->match($call['target']) instanceof CatalogEntry
            ? null
            : $this->patterns->match($call['target']);

        if ($pattern instanceof CatalogEntry) {
            // A predicate only matters where it decides something. Everywhere
            // else it is a number that gets logged, and the SQL is unaffected.
            if ($pattern->kind !== 'predicate' || $call['context']->insideCondition) {
                return $this->hit($file, $call, $pattern->kind, $pattern->reason);
            }

            return null;
        }

        $emitter = $this->ddlEmitters->match($call['target']);

        if ($emitter instanceof CatalogEntry && $call['context']->insideUnboundedLoop()) {
            return $this->hit(
                $file,
                $call,
                'loop_emitted_ddl',
                $emitter->reason.', from inside a loop whose iteration count comes from outside this file — under pretend that loop can run zero times and none of it is captured',
            );
        }

        return null;
    }

    /**
     * @param  array{node: Node, target: CallTarget, line: int, scope: string|null, context: CallContext}  $call
     */
    private function hit(string $file, array $call, string $kind, string $reason): PreScanHit
    {
        return new PreScanHit(
            self::RULE_ID,
            $file,
            $call['line'],
            sprintf(
                '%s at line %d %s. Pretend mode cannot capture what this migration really emits; run it in shadow mode, which executes against a throwaway database and can answer.',
                $this->label($kind),
                $call['line'],
                $reason,
            ),
            $call['target']->description,
        );
    }

    /** The human label for a pattern family, so the reason opens with what was found. */
    private function label(string $kind): string
    {
        return match ($kind) {
            'materialization' => 'A query result read',
            'iteration' => 'An iteration over query results',
            'predicate' => 'A branch on a query result',
            default => 'A schema or data change',
        };
    }
}
