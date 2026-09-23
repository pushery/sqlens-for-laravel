<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Pushery\SQLens\Catalog\RuleRegistryExport;
use Pushery\SQLens\Corpus\CorpusCollection;
use Pushery\SQLens\Corpus\CorpusLoader;
use Pushery\SQLens\Corpus\CorpusLoadFailure;
use Pushery\SQLens\Corpus\CorpusMetrics;
use Pushery\SQLens\Corpus\CorpusReport;
use Pushery\SQLens\Corpus\CorpusRun;
use Pushery\SQLens\Lint\LintOutcome;
use Pushery\SQLens\Lint\LintRunner;
use Pushery\SQLens\Reporting\ReportedServerVersion;
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
        $declaredLevels = $this->declaredLevels($repositoryRoot);
        $serverVersions = [];

        foreach ($collections as $collection) {
            $connection = $this->connectionFor($collection);

            if ($connection === null) {
                // Named and fatal, for the same reason a collection that will not load is: a
                // measurement that quietly used the default connection would report a rate under
                // this collection's engine for SQL that engine never saw.
                $this->components->error(sprintf(
                    'The collection at `%s` targets `%s`, and no configured database connection uses that driver. '
                    .'Configure one (its name does not matter, only its driver) or take the collection out of the corpus.',
                    $collection->path,
                    $this->driverOf($collection),
                ));

                return self::FAILURE;
            }

            $outcome = $this->measure($repositoryRoot, $collection, $connection);

            // Recorded per collection, because the same collection measures differently on two
            // server versions: a rate without the version it was taken on is a rate about an
            // unnamed engine.
            $serverVersions[$collection->path] = $this->serverVersionOf($outcome, $connection);

            foreach (CorpusRun::classify($collection, $outcome->result->findings, $this->driverOf($collection), $declaredLevels) as $case) {
                $cases[] = $case;
            }
        }

        $ruleIds = array_keys($declaredLevels);
        $metrics = CorpusMetrics::of($cases, $ruleIds);

        // The catalog this rate describes, recorded WITH it. Without the pair, a rate and a catalog
        // drift apart silently and the release gate has nothing to compare.
        $report = CorpusReport::of($metrics, $collections, $ruleIds, $serverVersions);

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
     * The run the SHIPPED runner performs over one collection.
     *
     * `LintRunner` is resolved from the container rather than constructed here, and that is the
     * guardrail rather than a convenience: the measurement has to use the same engine
     * `sqlens:lint` uses. A second path that did roughly the same analysis would drift from the
     * shipped one exactly where the shipped one is subtle, and it would drift silently — both
     * would keep passing their own tests.
     *
     * The connection is the collection's, not the application's default. `null` here would take
     * whatever the runner is pointed at while the report carries the collection's `engine` in its
     * heading. The schema builder emits per-grammar SQL, so that would not be a smaller measurement
     * but a measurement of a different subject filed under the wrong name.
     *
     * The level and the category set are the measurement's own, never the host application's. The
     * rate is a claim about the whole rule pack, so every rule has to be given the chance to speak:
     * at the configured level — 0 unless a project raised it — the rules above it stay silent, and
     * the classifier would read that silence as a false negative where the corpus expects a failure
     * and as a correct silence where it expects none. Both are verdicts about rules that never ran,
     * and the second one flatters the result.
     */
    private function measure(string $repositoryRoot, CorpusCollection $collection, string $connection): LintOutcome
    {
        return $this->laravel->make(LintRunner::class)->run(
            $connection,
            [$repositoryRoot.'/'.$collection->path],
            // `Pretend` rather than `Shadow`: a corpus measurement must not create a database.
            // Shadow capture is the more thorough mode and it is also the one that needs a server
            // it may write to — a measurement that required that could not run on a laptop, and a
            // measurement nobody runs is not a measurement.
            CaptureMode::Pretend,
            level: CorpusRun::measuredLevel(),
            // Every category, whatever the host configured. A convention rule left out of the run
            // would take its corpus cases with it and shrink the denominator the rate is taken over.
            categories: [],
        );
    }

    /**
     * The version of the server this collection was measured against, as the run met it.
     *
     * A run reports one entry per addressed connection and says so even when no server answered:
     * the version then reads `unknown (no server version could be determined)`, measured over a
     * refused connection and over an engine the rule pack does not support. So the absent case is
     * the runner's own wording rather than a gap this method invents, and the null tail is for a
     * context that carries no entry at all — which nothing in this command produces.
     *
     * @return array{version: string, source: string}|null
     */
    private function serverVersionOf(LintOutcome $outcome, string $connection): ?array
    {
        return array_values(array_map(
            static fn (ReportedServerVersion $version): array => [
                'version' => $version->version,
                'source' => $version->source->value,
            ],
            array_filter(
                $outcome->context->serverVersions,
                static fn (ReportedServerVersion $version): bool => $version->connection === $connection,
            ),
        ))[0] ?? null;
    }

    /**
     * The connection a collection is measured over: the first configured one whose DRIVER is the
     * collection's engine.
     *
     * By driver rather than by name, because the name is the host application's to choose — this
     * package's own test environment ships `mysql`, `pgsql` and `sqlite`, a consumer's may ship
     * `analytics` and `legacy`. Null when nothing matches, and the caller refuses rather than
     * falling back: a fallback here is exactly the silent substitution this command exists to
     * measure away.
     */
    private function connectionFor(CorpusCollection $collection): ?string
    {
        $engine = $this->driverOf($collection);

        // Through the container rather than the `config()` helper, and that is a shipped-code rule
        // rather than a style: this package declares the slim `illuminate/*` components, so a
        // consumer installing without `laravel/framework` gets a clean install and a fatal call.
        // Nothing local can see that — testbench pulls the framework into the vendor tree — which
        // is why a guard reads the source instead.
        $connections = $this->laravel->make(Repository::class)->get('database.connections');

        foreach (is_array($connections) ? $connections : [] as $name => $configured) {
            if (is_array($configured) && ($configured['driver'] ?? null) === $engine) {
                return (string) $name;
            }
        }

        return null;
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
     * Keyed by id and carrying the level each rule declares, because a corpus case belongs to its
     * rule's level whether or not the rule spoke in this run.
     *
     * @return array<string, int>
     */
    private function declaredLevels(string $repositoryRoot): array
    {
        // No catch, deliberately. The registry is a generated artifact this repository ships and a
        // gate validates; a malformed one is a broken build, not a condition to degrade around.
        // Swallowed into an empty list it would produce a report whose blind-spot list named EVERY
        // rule — a dramatic number with a boring cause, and nothing pointing at the cause.
        /** @var array{entries?: list<array{id?: string, level?: int}>} $registry */
        $registry = json_decode(
            (string) file_get_contents($repositoryRoot.'/'.RuleRegistryExport::BUNDLED_FILE),
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        $levels = [];

        foreach ($registry['entries'] ?? [] as $entry) {
            $id = (string) ($entry['id'] ?? '');

            if ($id !== '') {
                $levels[$id] = (int) ($entry['level'] ?? 0);
            }
        }

        // Sorted by id so the rule list the report carries is the same on every machine.
        ksort($levels);

        return $levels;
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
