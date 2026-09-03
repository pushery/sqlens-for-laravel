<?php

declare(strict_types=1);

namespace Pushery\SQLens\Tools;

/**
 * Where one statement sits in the document handed to the tool — ONE-based, inclusive on both
 * ends, the way a text editor counts.
 *
 * The counting base is in the property names on purpose. Squawk answers in ZERO-based lines
 * (measured, not assumed), so this file and the tool's output disagree by one at every single
 * finding. That is the quietest defect available here: an off-by-one does not fail, it puts the
 * finding on the neighboring statement and looks entirely plausible doing it. Naming the base
 * means the conversion has to be written out rather than assumed away.
 */
final readonly class ToolStatementSpan
{
    public function __construct(
        /** Which statement of the migration this is, in capture order. */
        public int $statementIndex,
        /** First line of the statement in the handed-over document, 1-based. */
        public int $firstLineOneBased,
        /** Last line, 1-based and inclusive — equal to the first for a single-line statement. */
        public int $lastLineOneBased,
    ) {}

    /** Whether a 1-based line of the handed-over document falls inside this statement. */
    public function contains(int $lineOneBased): bool
    {
        return $lineOneBased >= $this->firstLineOneBased && $lineOneBased <= $this->lastLineOneBased;
    }
}
