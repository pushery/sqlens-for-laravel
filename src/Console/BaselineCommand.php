<?php

declare(strict_types=1);

namespace Pushery\SQLens\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Translation\Translator;
use Pushery\SQLens\Canonical\Fingerprint;
use Pushery\SQLens\Drivers\DriverResolutionFailure;
use Pushery\SQLens\Drivers\UnsupportedDriverMessage;
use Pushery\SQLens\Exceptions\UnreadableBaseline;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Lint\LintRunner;
use Pushery\SQLens\Reporting\Baseline\BaselineEntry;
use Pushery\SQLens\Reporting\Baseline\BaselineFile;
use Pushery\SQLens\Reporting\Baseline\BaselineSerializer;
use Pushery\SQLens\Reporting\Baseline\BaselineSubject;
use Pushery\SQLens\Reporting\Baseline\FindingFingerprint;
use Pushery\SQLens\Subjects\CaptureMode;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * `sqlens:baseline` — freeze the current findings into a repo file so an existing
 * project can adopt SQLens without drowning in its first run: from then on the
 * linter reports only what is NEW.
 *
 * The baseline is a REPO ARTIFACT, never a database write — primum non nocere holds
 * here as everywhere. The file the command writes is deterministic by construction
 * (the serializer sorts stably, one finding per line, a trailing newline, no
 * timestamp/host/absolute path), so two runs on the same state produce byte-
 * identical output and a merge conflict between two branches resolves line by line.
 *
 * Only FAIL findings are frozen. An undetermined is never suppressed by a baseline
 * (a check that could not run is not a finding somebody accepted — see
 * BaselineSuppressionSource), and a pass is not gated, so neither belongs in the
 * accepted-findings ledger.
 *
 * `--update` merges the current fails into an existing baseline (additive: a
 * finding already recorded stays, a new one is added, a fixed one is left in place
 * until a fresh write drops it); a bare run writes the current state. `--dry-run`
 * reports what would be written without touching the file. An unreadable existing
 * baseline — a hand-broken JSON, an unknown schema version — is a named
 * misconfiguration, never a silent overwrite.
 */
final class BaselineCommand extends Command
{
    use ResolvesProfile;

    /** @var string */
    protected $signature = 'sqlens:baseline
        {--connection= : The database connection to lint; defaults to the resolved sqlens/default connection}
        {--path=* : A migration path to lint; repeatable. Defaults to the application’s registered migration paths}
        {--profile= : The environment profile — local, ci, or predeploy. Overrides SQLENS_PROFILE and the configured profile}
        {--update : Merge the current findings into the existing baseline instead of replacing it}
        {--dry-run : Report what would be written without touching the file}';

    /** @var string */
    protected $description = 'Freeze the current findings into a baseline file so future runs report only new ones.';

    public function handle(LintRunner $runner, Translator $translator, Repository $config, BaselineSerializer $serializer): int
    {
        // The active profile is resolved the same way here as in the lint command —
        // flag over SQLENS_PROFILE over config over the default — so a baseline is
        // frozen under the same environment profile a lint run would apply, and an
        // unknown value is named rather than silently defaulted.
        $profile = $this->resolveProfile($config);

        if (! $profile->isValid()) {
            $this->stderr()->writeln($this->profileRejectionMessage($profile));

            return ExitCode::Misconfiguration->value;
        }

        // The write target is resolved BEFORE the run: a baseline with nowhere to go
        // is a misconfiguration named up front, not after a wasted capture.
        $path = $this->resolvePath($config);

        if ($path === null) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.baseline_no_path'));

            return ExitCode::Misconfiguration->value;
        }

        $connection = $this->option('connection');
        // applyBaseline: false — this command WRITES the baseline, so it must see every
        // finding, not the ones the previous baseline already accepted (which would make
        // a second run freeze an empty file). Config and annotation suppression still
        // apply: a finding handled by those needs no baselining.
        $outcome = $runner->run(is_string($connection) ? $connection : null, $this->migrationPaths(), CaptureMode::Pretend, applyBaseline: false);

        // An unsupported engine linted nothing, so there is nothing to baseline —
        // the same named misconfiguration the lint command returns.
        if ($outcome->isUnsupported()) {
            $failure = $outcome->unsupported;
            $driver = $config->get("database.connections.{$outcome->connectionName}.driver");

            // isUnsupported() guarantees the failure is present; the guard keeps the type honest.
            if ($failure instanceof DriverResolutionFailure) {
                $this->stderr()->writeln(new UnsupportedDriverMessage($translator)->for(
                    $failure,
                    $outcome->connectionName,
                    is_string($driver) ? $driver : 'unknown',
                ));
            }

            return $outcome->exitCode->value;
        }

        $entries = $this->entriesFrom($outcome->result);

        // --update reads the existing file and merges; an unreadable one is named,
        // never silently replaced (that would discard a project's accepted findings).
        if ($this->option('update') === true && is_file($path)) {
            try {
                $existing = $serializer->deserialize((string) file_get_contents($path), $path);
            } catch (UnreadableBaseline $failure) {
                $this->stderr()->writeln($failure->getMessage());

                return ExitCode::Misconfiguration->value;
            }

            $entries = $this->merge($existing->entries, $entries);
        }

        $baseline = BaselineFile::of($entries);
        $bytes = $serializer->serialize($baseline);

        if ($this->option('dry-run') === true) {
            $this->line($this->translate('sqlens::messages.commands.baseline_dry_run', ['count' => count($baseline->entries), 'path' => $path]));

            return ExitCode::Clean->value;
        }

        if (@file_put_contents($path, $bytes) === false) {
            $this->stderr()->writeln($this->translate('sqlens::messages.commands.baseline_unwritable', ['path' => $path]));

            return ExitCode::Misconfiguration->value;
        }

        $this->line($this->translate('sqlens::messages.commands.baseline_written', ['count' => count($baseline->entries), 'path' => $path]));

        return ExitCode::Clean->value;
    }

    /** The baseline file to write, from the configured `sqlens.baseline.path`, or null. */
    private function resolvePath(Repository $config): ?string
    {
        $configured = $config->get('sqlens.baseline.path');

        return is_string($configured) && $configured !== '' ? $configured : null;
    }

    /**
     * The migration paths to lint: the repeated `--path` options, or null (the
     * runner's default — the application's registered migration paths).
     *
     * @return list<string>|null
     */
    private function migrationPaths(): ?array
    {
        $paths = $this->option('path');

        // No `is_array()` guard: the option is declared `--path=*`, so Symfony hands back an
        // array or nothing else. A check PHPStan can prove always true is a branch no test can
        // reach and no reader can trust — it reads as defensiveness while defending nothing.
        if ($paths === []) {
            return null;
        }

        return array_values(array_filter($paths, is_string(...)));
    }

    /**
     * The baseline entries for a result: one per FAIL finding, each fingerprinted by
     * rule id and location. Findings that carry no canonical statement (every finding
     * a run produces today — capture outcomes, pre-scan hits) have no statement
     * excerpt, so the excerpt is empty and the identity is (rule id, location); a
     * subject-rule finding will carry its canonical excerpt when the rule packs land.
     *
     * @return list<BaselineEntry>
     */
    private function entriesFrom(Result $result): array
    {
        $protos = [];

        foreach ($result->findings as $finding) {
            // Only a FAIL, and stated as an allowlist rather than as a list of exclusions. A
            // baseline is a record of things somebody looked at and decided to live with, and the
            // other three outcomes are not that: a pass has nothing to accept, an undetermined is a
            // question rather than a finding — accepting it would silence the answer along with the
            // question — and a not-applicable never happened on this instance at all. Written the
            // other way round, each new outcome would default INTO the file until somebody
            // remembered to exclude it.
            if ($finding->status->outcome !== Outcome::Fail) {
                continue;
            }

            $protos[] = [
                'fingerprint' => FindingFingerprint::of($finding->ruleId, $finding->location, Fingerprint::fromValue('')),
                'ruleId' => $finding->ruleId,
                'subject' => BaselineSubject::label($finding->location),
                // The axis travels into the file. A baseline is a list of things somebody looked at
                // and decided to live with, and living with a level-2 idiom finding is a different
                // decision from living with a critical security one. Without these two fields a
                // reviewer reading the file a year later cannot tell which accepted entries deserve
                // a second look — and "everything in here was fine once" is how a baseline rots.
                'category' => $finding->category,
                'severity' => $finding->severity,
            ];
        }

        return BaselineEntry::assign($protos);
    }

    /**
     * Merge new entries into the existing ones, additively: every existing entry is
     * kept, and a new entry is added only when its key is not already recorded, so a
     * repeated run never duplicates a finding already in the baseline.
     *
     * @param  list<BaselineEntry>  $existing
     * @param  list<BaselineEntry>  $fresh
     * @return list<BaselineEntry>
     */
    private function merge(array $existing, array $fresh): array
    {
        $seen = [];

        foreach ($existing as $entry) {
            $seen[$entry->key()] = true;
        }

        $merged = $existing;

        foreach ($fresh as $entry) {
            if (! isset($seen[$entry->key()])) {
                $merged[] = $entry;
                $seen[$entry->key()] = true;
            }
        }

        return $merged;
    }

    /** The error stream — diagnostics go here, never onto STDOUT. */
    private function stderr(): OutputInterface
    {
        return $this->output->getErrorStyle();
    }
}
