<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\MigrationStatementDigest;

/**
 * Everything one capture run produced, in a fixed order.
 *
 * The order is established HERE and never inherited from whatever order the
 * captor happened to emit results in — a filesystem listing, a glob, or a
 * generator's timing would all make the same repository produce different output
 * on two machines, which is precisely the determinism break the third principle
 * forbids.
 *
 * Aggregating these results into one three-valued verdict is deliberately NOT
 * this class's job; it holds and orders, it does not judge.
 */
final readonly class CaptureRun
{
    /**
     * @param  list<CaptureResult>  $results
     */
    private function __construct(
        public array $results,
        public CaptureMode $mode,
    ) {}

    /**
     * Build a run, sorting the results into their canonical order.
     *
     * The key is (migration file basename, section) — the basename carries
     * Laravel's timestamp prefix, so it fixes migration order, and the section
     * keeps a roundtrip's three passes in the order they actually ran rather
     * than interleaving them.
     *
     * @param  iterable<CaptureResult>  $results
     */
    public static function of(iterable $results, CaptureMode $mode): self
    {
        $ordered = is_array($results) ? array_values($results) : iterator_to_array($results, false);

        usort(
            $ordered,
            static fn (CaptureResult $a, CaptureResult $b): int => [basename($a->file), self::sectionRank($a->section)]
                <=> [basename($b->file), self::sectionRank($b->section)],
        );

        return new self($ordered, $mode);
    }

    /**
     * The run order of a section. Not the enum's declaration order by accident —
     * written out, so reordering the enum cases (a cosmetic change) can never
     * silently reorder captured output.
     */
    private static function sectionRank(CaptureSection $section): int
    {
        return match ($section) {
            CaptureSection::Up => 0,
            CaptureSection::Down => 1,
            CaptureSection::UpAgain => 2,
        };
    }

    /** How many migration results this run holds. */
    public function count(): int
    {
        return count($this->results);
    }

    /**
     * Every statement of the run, in run order.
     *
     * @return list<CapturedStatement>
     */
    public function statements(): array
    {
        $statements = [];

        foreach ($this->results as $result) {
            foreach ($result->statements as $statement) {
                $statements[] = $statement;
            }
        }

        return $statements;
    }

    /**
     * The run's statements as canonical digests, grouped by section — the material a rule needs
     * when the question is about an ABSENCE and one migration cannot settle it.
     *
     * See {@see MigrationContext::$runStatements} for why any rule looks past its own file at all.
     * Two things are deliberate here:
     *
     * - **Grouped by SECTION**, not flattened. A roundtrip run captures `up`, `down` and `up`
     *   again; a statement in the rollback leg is not part of what the forward leg builds, and a
     *   rule judging an `up` statement against a `down` leg's indexes would be reading a schema
     *   that never exists at the same time.
     * - **Only the results that PASSED.** An undetermined capture produced no statements at all,
     *   and a failed one produced whatever ran before it threw; neither is a basis for concluding
     *   that something is absent from the run.
     *
     * @return array<string, list<MigrationStatementDigest>>
     */
    public function statementDigestsBySection(): array
    {
        $bySection = [];

        foreach ($this->results as $result) {
            if (! $result->isPass()) {
                continue;
            }

            $key = $result->section->value;
            $bySection[$key] = [...($bySection[$key] ?? []), ...$result->statementDigests()];
        }

        return $bySection;
    }

    /**
     * The results that could not be determined, each still carrying its reason.
     * Reporting reads this rather than filtering itself, so no caller can
     * accidentally drop the reason on the way.
     *
     * @return list<CaptureResult>
     */
    public function undetermined(): array
    {
        return array_values(array_filter(
            $this->results,
            static fn (CaptureResult $result): bool => $result->isUndetermined(),
        ));
    }

    /**
     * A deterministic array projection.
     *
     * @return array{mode: string, results: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'mode' => $this->mode->value,
            'results' => array_map(
                static fn (CaptureResult $result): array => $result->toArray(),
                $this->results,
            ),
        ];
    }
}
