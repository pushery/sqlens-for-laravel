<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * Turns a line number an external tool reported back into a statement of a migration.
 *
 * A pure function over a payload: no database, no filesystem, no subprocess. Same input, same
 * triple, on a laptop and in CI — which is not a nicety here. A position is what a baseline entry
 * is anchored to, so a mapping that varied between runs would make yesterday's accepted findings
 * come back as new ones tomorrow.
 *
 * Tool-neutral by design and by test. Squawk is the first caller; the Postgres language server and
 * plpgsql_check report positions the same way, and each of them growing its own copy of this
 * arithmetic is three more chances to be off by one.
 *
 * A position that cannot be placed degrades THAT FINDING, with a named cause, and never guesses.
 * The guess available here is a very tempting one — attribute it to statement 0 — and it does not
 * look like an error afterwards. It looks like a finding on the first statement.
 */
final readonly class ToolPositionMapper
{
    /**
     * Map a ONE-based line, the way a text editor counts.
     *
     * The base is in the method name because the tools disagree about it, and the disagreement is
     * silent: Squawk answers zero-based (measured), so a caller that forgot would be off by one on
     * every finding — landing on the neighboring statement, which is exactly as plausible as the
     * right answer.
     */
    public function atLine(ToolPayload $payload, int $lineOneBased): ToolPositionResult
    {
        if ($lineOneBased < 1) {
            return ToolPositionResult::unmappable(ToolPositionUnmappable::NotAPosition);
        }

        foreach ($payload->spans as $span) {
            if ($span->contains($lineOneBased)) {
                return $this->resolve($payload, $span);
            }
        }

        return ToolPositionResult::unmappable($this->missReason($payload, $lineOneBased));
    }

    /** Map a ZERO-based line, for the tools that count that way — the conversion, written once. */
    public function atZeroBasedLine(ToolPayload $payload, int $lineZeroBased): ToolPositionResult
    {
        // Guarded before the shift rather than after it: -1 would otherwise become line 0 and then
        // fail as "not a position", which is true but describes the arithmetic rather than the input.
        if ($lineZeroBased < 0) {
            return ToolPositionResult::unmappable(ToolPositionUnmappable::NotAPosition);
        }

        return $this->atLine($payload, $lineZeroBased + 1);
    }

    /** The statement a span points at — which the payload is expected, not assumed, to carry. */
    private function resolve(ToolPayload $payload, ToolStatementSpan $span): ToolPositionResult
    {
        $statement = $payload->statements[$span->statementIndex] ?? null;

        if ($statement === null) {
            return ToolPositionResult::unmappable(ToolPositionUnmappable::UnknownStatement);
        }

        return ToolPositionResult::at(new ToolPosition(
            file: $statement->origin->file,
            migrationClass: $statement->origin->migrationClass,
            // The origin's index, not the span's: the span says where the statement sits in the
            // document we assembled, the origin says which statement of the migration it is. They
            // agree for a payload built from one migration and stop agreeing the moment a run
            // hands several migrations to one invocation.
            statementIndex: $statement->origin->statementIndex,
            direction: $statement->origin->direction,
            targets: $statement->targets,
        ));
    }

    /**
     * Which kind of miss this was — past the end, or in a gap.
     *
     * Worth telling apart because they mean different things about the caller. Past the end is a
     * tool reporting on text that is not there, and in a gap is a document assembled with
     * something between the statements.
     */
    private function missReason(ToolPayload $payload, int $lineOneBased): ToolPositionUnmappable
    {
        $lastLine = 0;

        foreach ($payload->spans as $span) {
            $lastLine = max($lastLine, $span->lastLineOneBased);
        }

        return $lineOneBased > $lastLine
            ? ToolPositionUnmappable::BeyondLastStatement
            : ToolPositionUnmappable::BetweenStatements;
    }
}
