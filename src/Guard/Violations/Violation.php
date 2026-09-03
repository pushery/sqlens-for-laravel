<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Violations;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Severity\Severity;

/**
 * One runtime guardrail violation, in a fixed field set a log aggregator can act on.
 *
 * ## Why a type rather than a message and a loose array
 *
 * The field that matters most is {@see $outcome}, and it has to be a FIELD. A guardrail that could
 * not establish anything and one that found a real problem both produce a line in a log, and if the
 * only thing separating them is English prose, an aggregator counts them together — which is the
 * silent green this package refuses, arriving through the one channel nobody diffs.
 *
 * ## It reuses the core vocabulary rather than restating it
 *
 * {@see Outcome}, {@see Category} and {@see Severity} come from the finding model. A second set of
 * three-valued statuses in this namespace would drift from the first the day one of them gained a
 * case, and a consumer reading both would have two vocabularies for one idea.
 *
 * The reverse — using `Finding` itself — was measured and rejected: a `Finding` requires a
 * documentation URL, a stability tier, a level and a `Location` in a migration or a catalog, and a
 * runtime violation has none of those. Filling them with placeholders to satisfy a constructor
 * would put five invented values into every log line.
 *
 * ## There is no `occurred_at`
 *
 * Deliberately, and it is the one place this type departs from its ticket. The logging stack stamps
 * every record already, and a timestamp inside the context would make two identical violations
 * produce two different context arrays — which the same ticket's determinism line forbids. A field
 * that breaks a promise the ticket also makes is a field that does not belong.
 */
final readonly class Violation
{
    /**
     * @param  string  $type  a stable machine key: `lazy_loading`, `slow_query`, `runtime_ddl`, …
     * @param  string|null  $reason  MANDATORY when the outcome is undetermined, absent otherwise
     * @param  array<array-key, mixed>  $bindings  Laravel's own shape — NAMED bindings are keyed by
     *                                             name, so a `list` would refuse the statements
     *                                             this suite most wants to report
     * @param  array<string, mixed>  $context  everything else, sorted by key before it is logged
     */
    private function __construct(
        public string $type,
        public Outcome $outcome,
        public Category $category,
        public ?Severity $severity,
        public string $message,
        public ?string $connection,
        public ?string $sql,
        public array $bindings,
        public ?string $reason,
        public array $context,
    ) {}

    /**
     * A real violation: something happened and this is what it was.
     *
     * @param  array<array-key, mixed>  $bindings
     * @param  array<string, mixed>  $context
     */
    public static function found(
        string $type,
        Category $category,
        string $message,
        ?string $connection = null,
        ?string $sql = null,
        array $bindings = [],
        array $context = [],
        ?Severity $severity = null,
    ): self {
        return new self($type, Outcome::Fail, $category, $severity, $message, $connection, $sql, $bindings, null, $context);
    }

    /**
     * A guardrail that could not establish anything, with the reason named.
     *
     * The reason is a REQUIRED argument rather than an optional one, which is the same construction
     * `FindingStatus::undetermined()` uses and for the same purpose: an anonymous undetermined is
     * unbuildable, so nobody can produce one by forgetting.
     *
     * @param  array<string, mixed>  $context
     */
    public static function undetermined(
        string $type,
        Category $category,
        string $message,
        string $reason,
        ?string $connection = null,
        ?string $sql = null,
        array $context = [],
    ): self {
        return new self($type, Outcome::Undetermined, $category, null, $message, $connection, $sql, [], $reason, $context);
    }

    /**
     * The log context, sorted and complete.
     *
     * Sorted by key so two identical violations produce byte-identical records: a log diff is how
     * somebody notices something changed, and an unstable key order makes every diff a change.
     *
     * @param  string|null  $sql  already truncated by the logger, which owns the length
     * @param  array<array-key, mixed>|null  $bindings  already redacted, or null to omit them
     * @return array<string, mixed>
     */
    public function contextFor(string $profile, ?string $sql, ?array $bindings): array
    {
        $context = [
            ...$this->context,
            'sqlens_guard' => $profile,
            'violation' => $this->type,
            // The FIELD that separates a finding from a failure to look. Present on every record,
            // including the ordinary ones, because a status that appears only in the exceptional
            // case is a status a query has to test for absence.
            'status' => $this->outcome->value,
            'category' => $this->category->value,
        ];

        if ($this->severity instanceof Severity) {
            $context['severity'] = $this->severity->value;
        }

        if ($this->reason !== null) {
            $context['reason'] = $this->reason;
        }

        if ($this->connection !== null) {
            $context['connection'] = $this->connection;
        }

        if ($sql !== null) {
            $context['sql'] = $sql;
        }

        if ($bindings !== null) {
            $context['bindings'] = $bindings;
        }

        ksort($context);

        return $context;
    }
}
