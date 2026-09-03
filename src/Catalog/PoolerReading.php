<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

/**
 * A pooler verdict together with the signals that produced it.
 *
 * The signals travel because the verdict alone is not actionable. "This connection is pooled" sends
 * a reader to guess what gave it away; "the backend process changed between two consecutive
 * statements" tells them what was measured and lets them disagree with it. A heuristic that cannot
 * be argued with is one people learn to switch off.
 */
final readonly class PoolerReading
{
    /** @param  list<string>  $signals  what was observed, in the order it was observed */
    private function __construct(public PoolerVerdict $verdict, public array $signals) {}

    /** @param  list<string>  $signals */
    public static function pooled(array $signals): self
    {
        return new self(PoolerVerdict::Transaction, $signals);
    }

    /** @param  list<string>  $signals */
    public static function direct(array $signals = []): self
    {
        return new self(PoolerVerdict::None, $signals);
    }

    /** @param  list<string>  $signals */
    public static function undetermined(array $signals): self
    {
        return new self(PoolerVerdict::Undetermined, $signals);
    }

    /** Whether the audit has to withhold every instance-scoped judgment. */
    public function degradesInstanceScope(): bool
    {
        return $this->verdict !== PoolerVerdict::None;
    }

    /** A stable one-line rendering of what was seen, for a header or a finding. */
    public function describe(): string
    {
        return $this->signals === []
            ? $this->verdict->value
            : $this->verdict->value.' ('.implode('; ', $this->signals).')';
    }
}
