<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Canonical\Stages\StatementSplitter;

/**
 * One piece of a split batch, with the one fact a consumer cannot recover from the text.
 *
 * ## Why this exists next to a plain `list<string>`
 *
 * {@see StatementSplitter::split()} answers the question the canonicalization asks — "which
 * statements are in this batch" — and a client directive is noise there. A formatter asks a
 * different question: it has to WRITE THE FILE BACK, so a directive it drops is a line the user
 * loses.
 *
 * Both answers come from one walk over the batch. Two walks would be two tokenizers, free to
 * disagree about where a dollar-quoted body ends — which is the defect this splitter's own docblock
 * exists to forbid.
 */
final readonly class StatementPart
{
    public function __construct(
        /** The piece itself, trimmed exactly as `split()` trims a statement. */
        public string $text,
        /** What it is — SQL the server runs, or a directive only the client reads. */
        public StatementPartKind $kind,
    ) {}

    /** Sugar for the common filter, so a caller never spells the comparison itself. */
    public function isSql(): bool
    {
        return $this->kind === StatementPartKind::Sql;
    }
}
