<?php

declare(strict_types=1);

namespace Pushery\SQLens\Agent\Mcp;

/**
 * The answer for a run that happened and could not determine everything it looked at, or null for
 * one that could.
 *
 * ## The failure this exists to close
 *
 * Measured on the real tools, over one outcome: a shadow run whose throwaway database could not be
 * provisioned behind a transaction pooler. The guard had allowed the run, so no refusal was due, and
 * the engine judged every migration undetermined. `lint_pending` answered `undetermined` and named
 * `shadow_transaction_pooling`. `lint_shadow` answered `status: "ok"` with no reasons at all, and
 * said its findings came from a real run against a throwaway database, where none had been created.
 * One outcome, two answers, because the check lived inside one of the two tools.
 *
 * ## Read from the envelope, never re-derived
 *
 * The engine already decided what it could not determine and why, and the envelope counts each
 * reason. This lists the ones that occurred. A second reading in the agent layer would be a second
 * answer, free to disagree with the report a person sees for the same run.
 *
 * ## After the refusal, before the ordinary answer
 *
 * A run that never happened belongs to {@see RunRefusal}, whose reason is more exact than a count. A
 * run that happened and left questions open belongs here. Only a run with neither may answer `ok`.
 * Every tool that starts a lint run asks both, in that order, and nothing in PHP makes a new tool do
 * so. `RunRefusalTest` does: it reads every such tool and fails for one that leaves either out.
 */
final readonly class RunUnresolved
{
    /**
     * The undetermined answer for this run, or null when it determined everything it looked at.
     *
     * @param  array<string, mixed>  $envelope  the run as the JSON envelope renders it
     * @param  string  $summary  the sentence the tool would have said anyway, kept beside the reason.
     *                           A run can be both unjudgeable in part and cut, and a text client
     *                           that heard only the first would act on a short list believing it
     *                           complete.
     */
    public static function in(array $envelope, string $summary): ?ToolAnswer
    {
        $reasons = self::reasons($envelope);

        if ($reasons === []) {
            return null;
        }

        return ToolAnswer::undetermined(
            'the run could not determine everything it looked at: '.implode(', ', $reasons),
            [],
            $summary,
        );
    }

    /**
     * The undetermined reasons this run actually hit, from the envelope's own counts, sorted.
     *
     * @param  array<string, mixed>  $envelope
     * @return list<string>
     */
    public static function reasons(array $envelope): array
    {
        $summary = $envelope['summary'] ?? null;
        $counts = is_array($summary) ? ($summary['counts'] ?? null) : null;
        $reasons = is_array($counts) ? ($counts['undetermined_reason'] ?? null) : null;
        $hit = [];

        foreach (is_array($reasons) ? $reasons : [] as $reason => $count) {
            if (is_int($count) && $count > 0) {
                $hit[] = (string) $reason;
            }
        }

        sort($hit);

        return $hit;
    }
}
