<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

use Pushery\SQLens\Severity\Severity;

/**
 * How large an object has to be before a finding about it is worth more attention.
 *
 * ## Why the numbers are data and not constants
 *
 * A threshold is a maintained claim, not an implementation detail. Kept as data it shows up in a
 * diff as one reviewable line and can be explained in a changelog; scattered through classes it
 * changes silently and nobody can say when or why. That matters more than usual here, because these
 * numbers reach other people's pipelines: raising one turns somebody's passing deploy into a
 * blocked one.
 *
 * ## What a threshold may and may not do
 *
 * It raises a severity. It never creates a finding and never removes one — a small table does not
 * make an unsafe migration safe, it just does not make it worse. That asymmetry is the whole reason
 * statistics are allowed near the gate at all: a number that could silence a finding would make the
 * report depend on when somebody last ran ANALYZE.
 *
 * ## Why an unknown key is an error
 *
 * A project override naming an operation this build does not have is almost always a typo or a
 * rename, and the harm is silent: the value is ignored, the default stays in force, and the project
 * believes it configured something. The same rule the config validator applies everywhere else.
 */
final readonly class EscalationThresholds
{
    /** @param array<string, list<array{min_rows?: int, min_bytes?: int, raise_to: Severity}>> $byOperation */
    private function __construct(private array $byOperation) {}

    /**
     * Load the shipped artefact, with any project overrides folded in.
     *
     * @param  array<string, mixed>  $overrides  from `sqlens.preflight.thresholds`
     *
     * @throws UnknownEscalationOperation
     */
    public static function load(array $overrides = [], ?string $path = null): self
    {
        $raw = json_decode(
            (string) file_get_contents($path ?? __DIR__.'/../../resources/data/escalation-thresholds.json'),
            true,
        );

        $operations = is_array($raw) && is_array($raw['operations'] ?? null) ? $raw['operations'] : [];
        $parsed = [];

        foreach ($operations as $name => $definition) {
            $parsed[(string) $name] = self::stepsFrom(
                is_array($definition) && is_array($definition['thresholds'] ?? null) ? $definition['thresholds'] : [],
            );
        }

        foreach ($overrides as $name => $steps) {
            if (! array_key_exists((string) $name, $parsed)) {
                throw new UnknownEscalationOperation((string) $name, array_keys($parsed));
            }

            $parsed[(string) $name] = self::stepsFrom(is_array($steps) ? $steps : []);
        }

        return new self($parsed);
    }

    /**
     * The operations this build knows, sorted — so two loads produce one order.
     *
     * @return list<string>
     */
    public function operations(): array
    {
        $names = array_keys($this->byOperation);
        sort($names);

        return $names;
    }

    /**
     * The severity an object of this size earns for this operation, or null when it earns none.
     *
     * The HIGHEST matching step wins, and the steps are evaluated in declared order rather than
     * sorted by value: a table can exceed both the high and the critical threshold, and answering
     * with the first match would report the gentler of two truths.
     *
     * A null row count or size does not match anything. That is the statistics-unavailable case, and
     * it must not fall through to a threshold of zero — which would escalate every finding on every
     * table nobody has analyzed.
     */
    public function severityFor(string $operation, ?int $rows, ?int $bytes): ?Severity
    {
        return $this->stepFor($operation, $rows, $bytes)['raise_to'] ?? null;
    }

    /**
     * The same answer, with the step that produced it.
     *
     * Separate from {@see self::severityFor()} because a caller that only wants the verdict should
     * not have to know the shape of a step — and because the finding needs the THRESHOLD, not just
     * the severity: "critical" without "because this table is over 10 million rows" is a verdict
     * nobody can check.
     *
     * ## `matched_on` is not decoration
     *
     * A step may declare BOTH `min_rows` and `min_bytes` — no shipped one does, and a project
     * override may, which is why this matters now that the key is configurable. Deriving the
     * reported threshold from which KEY is present rather than from which COMPARISON matched put a
     * number in the report that was never reached: a step with `min_rows: 999999999` and
     * `min_bytes: 1000`, raised by a 5 000-byte object holding ten rows, reported "≥ 999 999 999
     * rows". Measured. Wrong in the one place a wrong number costs most — a line somebody reads
     * before deciding whether to deploy.
     *
     * When both comparisons match, both statements are true and `bytes` is reported: it is the
     * dimension the operation actually copies, and a fixed precedence keeps two runs over one
     * database from disagreeing.
     *
     * @return array{min_rows?: int, min_bytes?: int, raise_to: Severity, matched_on: 'rows'|'bytes', matched_threshold: int}|null
     */
    public function stepFor(string $operation, ?int $rows, ?int $bytes): ?array
    {
        $earned = null;

        foreach ($this->byOperation[$operation] ?? [] as $step) {
            $rowsMatch = isset($step['min_rows']) && $rows !== null && $rows >= $step['min_rows'];
            $bytesMatch = isset($step['min_bytes']) && $bytes !== null && $bytes >= $step['min_bytes'];

            if ($rowsMatch || $bytesMatch) {
                // The number REACHED, resolved here so no caller has to index an optional key and
                // guess which one is meaningful.
                // No fallbacks: reaching either branch proves the key it reads is present, because
                // the match that got us here required it.
                $earned = $bytesMatch
                    ? [...$step, 'matched_on' => 'bytes', 'matched_threshold' => $step['min_bytes']]
                    : [...$step, 'matched_on' => 'rows', 'matched_threshold' => $step['min_rows']];
            }
        }

        return $earned;
    }

    /**
     * @param  array<int|string, mixed>  $steps
     * @return list<array{min_rows?: int, min_bytes?: int, raise_to: Severity}>
     */
    private static function stepsFrom(array $steps): array
    {
        $parsed = [];

        foreach ($steps as $step) {
            if (! is_array($step)) {
                continue;
            }
            if (! is_string($step['raise_to'] ?? null)) {
                continue;
            }
            $severity = Severity::tryFrom($step['raise_to']);

            if (! $severity instanceof Severity) {
                continue;
            }

            $entry = ['raise_to' => $severity];

            if (is_int($step['min_rows'] ?? null)) {
                $entry['min_rows'] = $step['min_rows'];
            }

            if (is_int($step['min_bytes'] ?? null)) {
                $entry['min_bytes'] = $step['min_bytes'];
            }

            $parsed[] = $entry;
        }

        return $parsed;
    }
}
