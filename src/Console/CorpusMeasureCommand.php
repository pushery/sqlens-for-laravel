<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Pushery\SQLens\Catalog\RuleRegistryExport;
use Pushery\SQLens\Corpus\CorpusCollection;
use Pushery\SQLens\Corpus\CorpusLoader;
use Pushery\SQLens\Corpus\CorpusLoadFailure;
use Pushery\SQLens\Corpus\CorpusMetrics;
use Pushery\SQLens\Corpus\CorpusReport;
use Pushery\SQLens\Corpus\CorpusRun;
use Pushery\SQLens\Corpus\RuleCatalogFingerprint;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Lint\LintRunner;
use Pushery\SQLens\Subjects\CaptureMode;

/**
 * Measures the rule set against the false-positive corpus.
 *
 * ## Why this command is NOT part of the promised command surface
 *
 * From 1.0 the `sqlens:*` commands are public API: a command registered in the regular service
 * provider appears in every consuming application's `artisan list`, and appearing there is what
 * makes it a promise. This one measures THIS package against THIS package's corpus and would mean
 * nothing in a consumer's application — so it is registered only by the development provider, which
 * nothing auto-discovers.
 *
 * That is a mechanism rather than an intention: the package declares exactly one provider for
 * auto-discovery, and a negative test boots an ordinary application and asserts this name is absent
 * from its command list. An intention would be a sentence in a docblock, and a sentence does not
 * survive somebody adding a line to the wrong provider.
 *
 * ## The report is written, not printed
 *
 * A number on a terminal is gone when the terminal is. The artifact is what the release gate reads
 * and what a diff shows, so the console output is a summary of a file that already exists rather
 * than the result itself.
 */
final class CorpusMeasureCommand extends Command
{
    protected $signature = 'sqlens:corpus-measure
        {--corpus=tests/Fixtures/Corpus : Repo-relative corpus root}
        {--out=tests/Fixtures/Corpus/corpus-report.json : Where the report is written}';

    protected $description = 'Measure the rule set against the false-positive corpus (development only)';

    public function handle(): int
    {
        $repositoryRoot = dirname(__DIR__, 2);

        /** @var string $corpusRoot */
        $corpusRoot = $this->option('corpus');
        /** @var string $out */
        $out = $this->option('out');

        try {
            $collections = CorpusLoader::load($repositoryRoot, $corpusRoot);
        } catch (CorpusLoadFailure $failure) {
            // Named and fatal, never skipped. A collection that dropped out silently would shrink
            // both halves of the rate and leave a plausible number over a corpus nobody chose.
            $this->components->error($failure->getMessage());

            return self::FAILURE;
        }

        if ($collections === []) {
            // An empty corpus is reported as empty rather than as a clean result. A rate over zero
            // cases is not a good rate — it is no rate, and the two must not print alike.
            $this->components->warn(sprintf(
                'The corpus at `%s` holds no collection, so there is nothing to measure. A report '
                .'written now would carry a rate over zero cases, which reads exactly like a '
                .'flawless one.',
                $corpusRoot,
            ));

            return self::FAILURE;
        }

        $cases = [];

        foreach ($collections as $collection) {
            foreach (CorpusRun::classify($collection, $this->findingsFor($repositoryRoot, $collection), $this->driverOf($collection)) as $case) {
                $cases[] = $case;
            }
        }

        $ruleIds = $this->shippedRuleIds($repositoryRoot);
        $metrics = CorpusMetrics::of($cases, $ruleIds);

        // The catalog this rate describes, recorded WITH it. Without the pair, a rate and a catalog
        // drift apart silently and the release gate has nothing to compare.
        $report = CorpusReport::of($metrics, $collections, RuleCatalogFingerprint::of($ruleIds));

        $this->write($repositoryRoot.'/'.$out, $report);

        $this->components->info(sprintf(
            '%d collection(s), %d case(s) measured, %d not measured. Report: %s',
            count($collections),
            $metrics->measured(),
            $metrics->unmeasured(),
            $out,
        ));

        return self::SUCCESS;
    }

    /**
     * The findings the SHIPPED runner produces for one collection.
     *
     * `LintRunner` is resolved from the container rather than constructed here, and that is the
     * guardrail rather than a convenience: the measurement has to use the same engine
     * `sqlens:lint` uses. A second path that did roughly the same analysis would drift from the
     * shipped one exactly where the shipped one is subtle, and it would drift silently — both
     * would keep passing their own tests.
     *
     * @return list<Finding>
     */
    private function findingsFor(string $repositoryRoot, CorpusCollection $collection): array
    {
        $outcome = $this->laravel->make(LintRunner::class)->run(
            null,
            [$repositoryRoot.'/'.$collection->path],
            // `Pretend` rather than `Shadow`: a corpus measurement must not create a database.
            // Shadow capture is the more thorough mode and it is also the one that needs a server
            // it may write to — a measurement that required that could not run on a laptop, and a
            // measurement nobody runs is not a measurement.
            CaptureMode::Pretend,
        );

        return $outcome->result->findings;
    }

    /**
     * Which engine a collection is for.
     *
     * From the manifest, which the loader has already validated as present and non-empty — so this
     * cannot silently fall back to a default and report a PostgreSQL number under a MySQL heading.
     */
    private function driverOf(CorpusCollection $collection): string
    {
        return $collection->manifest['engine'];
    }

    /**
     * Every rule id this build ships, so the report can name its blind spots.
     *
     * Read from the generated registry rather than from the rule objects, because that artifact is
     * what a consumer reads and what the documentation gate holds — a second enumeration here would
     * be a second answer to "which rules exist".
     *
     * @return list<string>
     */
    private function shippedRuleIds(string $repositoryRoot): array
    {
        // No catch, deliberately. The registry is a generated artifact this repository ships and a
        // gate validates; a malformed one is a broken build, not a condition to degrade around.
        // Swallowed into an empty list it would produce a report whose blind-spot list named EVERY
        // rule — a dramatic number with a boring cause, and nothing pointing at the cause.
        /** @var array{entries?: list<array{id?: string}>} $registry */
        $registry = json_decode(
            (string) file_get_contents($repositoryRoot.'/'.RuleRegistryExport::BUNDLED_FILE),
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        $ids = [];

        foreach ($registry['entries'] ?? [] as $entry) {
            $id = (string) ($entry['id'] ?? '');

            if ($id !== '') {
                $ids[] = $id;
            }
        }

        sort($ids);

        return array_values(array_unique($ids));
    }

    /** @param  array<string, mixed>  $report */
    private function write(string $path, array $report): void
    {
        $directory = dirname($path);

        if (! is_dir($directory)) {
            mkdir($directory, 0o755, true);
        }

        // Pretty-printed with unescaped slashes, and a trailing newline: the file is committed, so
        // its diff is read by people. `JSON_PRETTY_PRINT` alone would escape every path separator
        // and turn a readable line into `tests\/Fixtures\/…`.
        file_put_contents($path, json_encode(
            $report,
            JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        )."\n");
    }
}
