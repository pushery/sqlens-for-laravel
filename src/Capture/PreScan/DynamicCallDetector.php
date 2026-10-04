<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Name;
use Pushery\SQLens\Capture\CaptureRuleMetadata;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\PreScanDetector;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\RuleDocumentationUrl;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\VersionWindow;

/**
 * Holds back a migration that makes a call the pre-scan cannot resolve.
 *
 *     call_user_func([Http::class, 'post'], $url);   // the target is an argument
 *     Http::$method($url);                           // the method is a variable
 *     $send($url);                                   // the function is a variable
 *
 * The other detectors match what a call reaches against catalogs of known surfaces, and a call whose
 * target only exists at run time matches none of them. That is not an acquittal: the pre-scan cannot
 * say what it runs, so it cannot say that it is safe, and a pretend capture would run it for real.
 * The migration is undetermined, and the finding names the form of the call it could not follow.
 *
 * A call on the migration's own `$this`, `self` or `static` with a variable method name is not a
 * hit. It reaches a method of the migration, and once such a call is present the pre-scan reads every
 * method the migration has.
 */
final readonly class DynamicCallDetector implements PreScanDetector
{
    public const string RULE_ID = 'CAP.PRESCAN.DYNAMIC_CALL';

    public function metadata(): CaptureRuleMetadata
    {
        return new CaptureRuleMetadata(
            id: self::RULE_ID,
            category: Category::Safety,
            level: Level::Capturable,
            severity: null,
            // Stable: a call the pre-scan cannot resolve is a fact about the file, not a pattern with
            // a false-positive rate to measure. What the finding says is true of every hit.
            stability: StabilityTier::Stable,
            deprecation: null,
            versionWindow: VersionWindow::unbounded(),
            downtimeClass: null,
            downtimeClassRationale: 'A pre-scan hit describes no DDL — it is the reason a migration was not captured at all — so it has no downtime behavior to classify.',
            messagePrefix: 'Unresolvable call from migration',
            documentationUrl: RuleDocumentationUrl::for(self::RULE_ID),
            suites: PreScanMetadataAudit::defaultSuites(),
            badExample: <<<'PHP'
                public function up(): void
                {
                    // Which method runs is decided at run time, so no catalog can
                    // say whether it sends a request or only formats a string.
                    $method = config('backfill.transport');

                    Http::$method('https://example.test/deployed');
                }
                PHP,
            goodExample: <<<'PHP'
                public function up(): void
                {
                    Schema::table('users', fn (Blueprint $t) => $t->string('slug')->nullable());
                }

                // The notification is a step the deploy runs after the migration,
                // where the call is written out and can be read.
                PHP,
        );
    }

    public function detect(ScannedMigration $migration): array
    {
        $hits = [];
        $seenLines = [];

        foreach ($migration->migrationCalls() as $call) {
            if (! $call['target']->isDynamic) {
                continue;
            }

            if ($this->reachesOwnMethod($call['node'])) {
                continue;
            }

            if (in_array($call['line'], $seenLines, true)) {
                continue;
            }

            $hits[] = new PreScanHit(
                self::RULE_ID,
                $migration->file,
                $call['line'],
                sprintf(
                    'The migration makes %s at line %d, a call the static pre-scan cannot resolve, so it cannot say what the call runs or that it is safe. Pretend mode would run it for real. Write the call out, or move it into a step the deploy runs after the migration.',
                    $call['target']->description,
                    $call['line'],
                ),
                $call['target']->description,
            );
            $seenLines[] = $call['line'];
        }

        return $hits;
    }

    /** Whether a dynamic call can only reach a method of the migration itself. */
    private function reachesOwnMethod(Node $node): bool
    {
        if ($node instanceof MethodCall) {
            return $node->var instanceof Variable && $node->var->name === 'this';
        }

        return $node instanceof StaticCall
            && $node->class instanceof Name
            && in_array($node->class->toLowerString(), ['self', 'static'], true);
    }
}
