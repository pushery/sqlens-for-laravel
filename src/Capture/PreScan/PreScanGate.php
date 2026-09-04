<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture\PreScan;

use Pushery\SQLens\Capture\CaptureResult;
use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Contracts\Captor;
use Pushery\SQLens\Contracts\PreScanDetector;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\StabilityGate;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\DownLegDigest;
use Pushery\SQLens\Subjects\DownMethodState;

/**
 * The gate that turns a pre-scan hit into a safe consequence: a flagged migration
 * is NOT pretend-executed, and its result is `undetermined` with the hits that
 * flagged it and a pointer to shadow mode.
 *
 * Detecting a side effect is not the same as preventing one — this is where the
 * prevention happens. The side-effect detector can only say "this migration would
 * mail a customer"; the gate is what makes sure that migration never reaches the
 * pretend run where the mail would actually be sent. Recognition without this
 * gate would be a report written after the disaster.
 *
 * It is the ONE decision point for whether a migration enters the pretend path,
 * and it is deliberately detector-agnostic: every `PreScanDetector` — side
 * effects, result-dependent patterns, introspection guards, indirect calls —
 * runs through the same interface, and none gets a special path. The single-file fast path uses this same gate, so there is no second
 * place where the "should this run?" question is answered differently.
 *
 * It decorates the captor: clean migrations are handed to the inner captor
 * untouched, flagged ones never are. The inner captor keeps its own contract of
 * resolving nothing — the gate partitions an already-resolved list, it does not
 * discover what is pending.
 */
final readonly class PreScanGate implements Captor
{
    /**
     * @param  list<PreScanDetector>  $detectors
     * @param  Captor|null  $downLegCaptor  a PRETEND captor used to read what `down()` would emit —
     *                                      see {@see captureDownLeg()}. Null leaves the rollback leg
     *                                      unread, which rules must treat as "nobody looked".
     */
    public function __construct(
        private Captor $inner,
        private array $detectors,
        private MigrationFileScanner $scanner = new MigrationFileScanner,
        private ?Captor $downLegCaptor = null,
    ) {}

    /**
     * The gate wired with every pre-scan detector the package ships, over the
     * given inner captor. The additional side-effect surfaces and the
     * indirect-call allowlist come from the application's config; the defaults are
     * empty, and the lint command passes the resolved lists.
     *
     * @param  list<string>  $additionalSideEffects
     * @param  list<string>  $indirectCallAllowlist
     */
    public static function withDefaultDetectors(
        Captor $inner,
        array $additionalSideEffects = [],
        array $indirectCallAllowlist = [],
        ?Captor $downLegCaptor = null,
        ?StabilityGate $stability = null,
    ): self {
        $detectors = [
            new SideEffectFacadeDetector(additional: $additionalSideEffects),
            new ResultDependentDetector,
            new SchemaIntrospectionGuardDetector,
            new IndirectCallDetector(allowlist: $indirectCallAllowlist),
        ];

        // The maturity axis, applied HERE — at the one place the default list exists, rather than a
        // second time downstream. Two of these four are `preview`, and the gate never saw them: it
        // was applied to the rule registry only, so the promise the tier makes ("a new check runs
        // only on request, so a minor release cannot start failing a build over code nobody
        // touched") simply did not hold for the pre-scan layer. Both preview detectors fired in the
        // shipped default.
        //
        // It goes unnoticed because both produce useful findings — a user sees no error, just
        // findings the contract says they should have had to ask for.
        $gate = $stability ?? new StabilityGate;

        return new self($inner, array_values(array_filter(
            $detectors,
            static fn (PreScanDetector $detector): bool => $gate->admits($detector->metadata()->stability),
        )), downLegCaptor: $downLegCaptor);
    }

    public function capture(iterable $migrations, CaptureSection $section): CaptureRun
    {
        $clean = [];
        $flagged = [];

        /** @var array<string, DownMethodState> $downStates */
        $downStates = [];

        /** @var array<string, array<string, string>> $declaredEmpty */
        $declaredEmpty = [];

        foreach ($migrations as $migration) {
            $verdict = $this->judge($migration, $section, $downStates, $declaredEmpty);

            if ($verdict instanceof CaptureResult) {
                $flagged[] = $verdict;

                continue;
            }

            $clean[] = $migration;
        }

        $captured = $this->inner->capture($clean, $section)->results;

        // The `down()` state rides back onto the results the captor produced. It is read from the
        // parse this gate already did — attaching it here rather than parsing again is what keeps
        // the pre-scan at one parse per file, which is the fast path's whole budget.
        $captured = array_map(
            static fn (CaptureResult $result): CaptureResult => isset($downStates[$result->file])
                ? $result->withDownMethodState($downStates[$result->file])
                : $result,
            $captured,
        );

        // What the file declared about deliberate emptiness rides back the same way, and for the
        // same reason. Read for THIS section only: the run captures one direction at a time, and a
        // migration whose `up()` is deliberately empty on SQLite may still owe a real `down()`.
        $captured = array_map(
            static fn (CaptureResult $result): CaptureResult => ($declaredEmpty[$result->file] ?? []) !== []
                ? $result->withDeclaredEmptyOn($declaredEmpty[$result->file])
                : $result,
            $captured,
        );

        $downLegs = $this->captureDownLeg($clean, $section);

        $captured = array_map(
            static fn (CaptureResult $result): CaptureResult => isset($downLegs[$result->file])
                ? $result->withDownLeg($downLegs[$result->file])
                : $result,
            $captured,
        );

        return CaptureRun::of([...$captured, ...$flagged], $this->mode());
    }

    /**
     * What each of these migrations' `down()` would emit, keyed by file.
     *
     * Read here, and only here, for three reasons that all point at this class:
     *
     * - it is the one decorator wrapping EVERY capture mode, so a rule about `down()` gets the
     *   same material in pretend and in shadow — one reading, not a fast one and a correct one;
     * - it has already decided each of these files is safe to execute, so reading the rollback
     *   leg needs no second pre-scan and cannot run a migration the gate held back;
     * - the captor it uses is a PRETEND one whatever the mode is. A lint run must never RUN a
     *   rollback: `down()` is the one migration method whose job is to destroy things, and what
     *   a rule needs is the SQL it would emit, which pretend hands over without executing a line.
     *
     * Only the `up` section asks. A roundtrip calls this gate once per leg, and attaching a
     * rollback leg to the rollback's own result would say nothing and cost another capture.
     *
     * @param  list<PendingMigration>  $migrations  already past the gate
     * @return array<string, DownLegDigest> keyed by migration file path; empty when nothing looked
     */
    private function captureDownLeg(array $migrations, CaptureSection $section): array
    {
        if (! $this->downLegCaptor instanceof Captor || $section !== CaptureSection::Up || $migrations === []) {
            return [];
        }

        $legs = [];

        foreach ($this->downLegCaptor->capture($migrations, CaptureSection::Down)->results as $result) {
            $legs[$result->file] = $result->asDownLeg();
        }

        return $legs;
    }

    public function mode(): CaptureMode
    {
        return $this->inner->mode();
    }

    /**
     * Judge one migration: null lets it through to the captor, a CaptureResult is
     * the undetermined verdict that keeps it out of the pretend run.
     *
     * It also records the file's `down()` state into `$downStates`, because this is the one
     * place the parsed file exists — the scan result is discarded right after.
     *
     * @param  array<string, DownMethodState>  $downStates  keyed by migration file path
     * @param  array<string, array<string, string>>  $declaredEmpty  keyed by file, then driver => reason
     *
     * A file the scanner cannot parse is undetermined too, for its own reason — a
     * file whose syntax the scanner cannot follow is a file whose side effects it
     * also cannot see, so it never gets the benefit of the doubt and never runs.
     */
    private function judge(PendingMigration $migration, CaptureSection $section, array &$downStates, array &$declaredEmpty): ?CaptureResult
    {
        $scanned = $this->scanner->scan($migration->file);

        if ($scanned instanceof ScanFailure) {
            return CaptureResult::undetermined(
                $migration->file,
                $migration->migrationClass,
                $section,
                $this->mode(),
                $scanned->reason,
            );
        }

        // Recorded for every scannable file, flagged or not: a migration the pre-scan stops is
        // still a migration whose down() a later run will ask about.
        $downStates[$migration->file] = $scanned->downMethodState();

        // Recorded for every scannable file too, and for the section being captured: a declaration
        // is a fact about the file, not about whether the gate let it through.
        $declaredEmpty[$migration->file] = $scanned->driversDeclaredEmpty($section->direction()->value);

        $hits = $this->hits($scanned);

        if ($hits === []) {
            return null;
        }

        return CaptureResult::undetermined(
            $migration->file,
            $migration->migrationClass,
            $section,
            $this->mode(),
            UndeterminedReason::PreScanFlagged,
            $hits,
        );
    }

    /**
     * Every hit from every detector, in one deterministic order.
     *
     * All reasons stay visible — never "first hit wins" — because a migration can
     * be undetermined for several independent reasons at once, and hiding all but
     * one would send a user to fix a symptom while another remains. The sort by
     * (file, line, rule id) makes the order identical on every machine.
     *
     * @return list<PreScanHit>
     */
    private function hits(ScannedMigration $scanned): array
    {
        $hits = [];

        foreach ($this->detectors as $detector) {
            foreach ($detector->detect($scanned) as $hit) {
                $hits[] = $hit;
            }
        }

        usort($hits, static fn (PreScanHit $a, PreScanHit $b): int => $a->sortKey() <=> $b->sortKey());

        return $hits;
    }
}
