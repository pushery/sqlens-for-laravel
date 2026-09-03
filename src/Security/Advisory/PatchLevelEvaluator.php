<?php

declare(strict_types=1);

namespace Pushery\SQLens\Security\Advisory;

/**
 * Holds a server's reported version against the end-of-life data.
 *
 * Driver-neutral on purpose: PostgreSQL's `server_version` and MySQL's `version` are different
 * variables with the same shape, and the comparison is arithmetic on a cycle either way. Putting it
 * under one driver would have made the other import across the boundary the architecture forbids;
 * duplicating it would have made two answers to one question, and the second copy is always the one
 * nobody updates.
 *
 * Every branch returns a {@see PatchAssessment} rather than throwing. A version this data has never
 * seen is a normal Tuesday — the server is newer than the file, or older than anything it records —
 * and neither is a reason to take a security run down.
 */
final readonly class PatchLevelEvaluator
{
    /**
     * @param  string  $reported  the version exactly as the server named it, e.g. `18.4 (Homebrew)`
     * @param  string  $today  an ISO-8601 date; passed in rather than read from the clock, so the
     *                         same server and the same file produce the same verdict in a test
     *                         and in a run
     */
    public function evaluate(string $reported, string $product, EolData $data, string $today): PatchAssessment
    {
        $candidates = $this->parse($reported);

        if ($candidates === []) {
            return new PatchAssessment(PatchVerdict::VersionUnparsable, $reported, null, null, $data);
        }

        foreach ($candidates as [$cycleName, $patch]) {
            $cycle = $data->cycleFor($product, $cycleName);

            if ($cycle instanceof EolCycle) {
                return $this->judge($cycle, $cycleName, $patch, $reported, $data, $today);
            }
        }

        // Named with the FIRST candidate, which is the most specific reading. A message that said
        // "neither 8.4 nor 8 is known" would be true and useless; a reader wants the cycle they
        // believe they are running.
        return new PatchAssessment(PatchVerdict::CycleUnknown, $reported, $candidates[0][0], null, $data);
    }

    private function judge(EolCycle $cycle, string $cycleName, int $patch, string $reported, EolData $data, string $today): PatchAssessment
    {
        if ($cycle->endedBy($today)) {
            return new PatchAssessment(PatchVerdict::Ended, $reported, $cycleName, $cycle, $data);
        }

        // Null means this build records no patch levels at all, which is a statement about the DATA
        // and not about the server. Reported as undetermined rather than as a pass: "up to date" is
        // a claim, and nothing here is entitled to make it.
        if ($cycle->latestPatch === null) {
            return new PatchAssessment(PatchVerdict::PatchLevelUnknown, $reported, $cycleName, $cycle, $data);
        }

        $verdict = $this->behind($patch, $cycle->latestPatch) ? PatchVerdict::BehindLatestPatch : PatchVerdict::Current;

        return new PatchAssessment($verdict, $reported, $cycleName, $cycle, $data);
    }

    /**
     * Every way the version string could name a cycle, most specific first.
     *
     * The two engines count majors differently and neither says so in the string. PostgreSQL has
     * used a one-component major since 10, so `18.4` is major 18 at patch 4. MySQL uses two, so
     * `8.4.10` is cycle 8.4 at patch 10 — and `8.4` is that same cycle at patch 0, which reads
     * exactly like PostgreSQL's `18.4` and cannot be told apart from it by shape alone.
     *
     * So this does not decide. It offers both readings and lets the DATA choose: whichever cycle
     * the file actually carries is the one meant, because a file that knows `8.4` and not `8` has
     * already answered the question. That keeps the engine's numbering convention in the one place
     * it is written down rather than in a branch here that would have to be kept in step with it.
     *
     * Both engines put their own noise after the numbers — `18.4 (Homebrew)`, `8.4.10-log`,
     * `9.1.0-commercial` — so only the leading numeric run is read. A build suffix nobody predicted
     * must not turn a readable version into an unreadable one.
     *
     * @return list<array{0: string, 1: int}> cycle name and patch number, most specific first
     */
    private function parse(string $reported): array
    {
        if (preg_match('/^(\d+)(?:\.(\d+))?(?:\.(\d+))?/', trim($reported), $m) !== 1) {
            return [];
        }

        $major = $m[1];
        $minor = ($m[2] ?? '') !== '' ? $m[2] : null;
        $patch = ($m[3] ?? '') !== '' ? $m[3] : null;

        if ($minor === null) {
            return [[$major, 0]];
        }

        if ($patch !== null) {
            // Three components leave no ambiguity: `8.4.10` is cycle 8.4 at patch 10. The
            // one-component reading is offered anyway, because a data file that tracks PostgreSQL
            // majors would carry `18` for a hypothetical `18.4.1`.
            return [["{$major}.{$minor}", (int) $patch], [$major, (int) $minor]];
        }

        // Two components, and this is the genuinely ambiguous shape. `8.4` is a MySQL cycle at
        // patch 0; `18.4` is a PostgreSQL major at patch 4. Both readings are offered, two-part
        // first, because a file carrying the two-part name means it.
        return [["{$major}.{$minor}", 0], [$major, (int) $minor]];
    }

    /**
     * Whether the server's patch number is behind the one the data records.
     *
     * The recorded value is a full version string rather than a bare number, so the trailing
     * component is what is compared — `18.7` records patch 7, `8.4.12` records patch 12.
     */
    private function behind(int $patch, string $latest): bool
    {
        return preg_match('/(\d+)$/', $latest, $m) === 1 && $patch < (int) $m[1];
    }
}
