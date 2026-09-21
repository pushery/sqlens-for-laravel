<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Findings\CredentialRedactor;

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

    /**
     * ⚠️ The detail is REDACTED here rather than at the caller, and that is the whole shape of
     * the fix: eighteen producers wrote `Throwable::getMessage()` into this field with no
     * redactor at all, and `QueryException::formatMessage()` appends ` (Connection: …, Host: …,
     * Port: …, Database: …, SQL: …)` to every query exception on both engines. A refused catalog
     * read on a managed instance — which the collectors' own comments call the ordinary case —
     * therefore arrived wearing the connection's coordinates.
     *
     * At the sink, because a nineteenth producer inherits the redaction without knowing it exists.
     * Not at {@see Finding}, which would be a filter rather than a sink: the shape redactor removes
     * `role "…"`, `user "…"` and `database "…"`, and that is precisely what a SECURITY finding
     * about a role or a database is made of. This field carries error text and nothing else.
     *
     * Only this factory: `pooled()` and `direct()` carry signals this package composes itself, and
     * the probe's failure path is the one that carries a driver's words.
     *
     * @param  list<string>  $signals
     */
    public static function undetermined(array $signals): self
    {
        $redactor = new CredentialRedactor;

        return new self(
            PoolerVerdict::Undetermined,
            array_map($redactor->redact(...), $signals),
        );
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
