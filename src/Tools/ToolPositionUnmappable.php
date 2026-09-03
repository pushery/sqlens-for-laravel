<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * Why a position an external tool reported could not be turned back into a statement.
 *
 * Four causes and not one word, because the alternative to naming them is the failure this whole
 * unit exists to prevent: quietly attributing an unmappable position to statement 0. That does
 * not look like an error — it looks like a finding on the first statement of the migration, and
 * the baseline written from it then shifts the moment anything about the file changes.
 */
enum ToolPositionUnmappable: string
{
    /** The tool reported a line before the document starts — a negative or zero position. */
    case NotAPosition = 'not_a_position';

    /** The line lies past the last statement, or the document holds no statements at all. */
    case BeyondLastStatement = 'beyond_last_statement';

    /**
     * The line is inside the document but inside no statement.
     *
     * Impossible for the payload this package builds, whose statements are contiguous — and named
     * anyway, because the mapper is tool-neutral and a document assembled with separators is a
     * legitimate payload. The alternative is a mapper that silently attributes a separator line
     * to whichever statement happens to be adjacent.
     */
    case BetweenStatements = 'between_statements';

    /**
     * The span points at a statement the payload does not carry.
     *
     * A payload whose two halves disagree. It cannot happen through the builder, and it is worth
     * a name for exactly that reason: if it ever does, every finding still maps cleanly — to the
     * wrong statement — and nothing else in the system would notice.
     */
    case UnknownStatement = 'unknown_statement';
}
