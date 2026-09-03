<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Classification;

use Pushery\SQLens\Canonical\TargetRole;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * One element of a statement signature — a keyword to match, a run of skippable
 * modifiers, a target identifier to capture, or a keyword to seek to. Built only
 * through the named constructors so an ill-formed element (a Keyword with no word,
 * a Target with no type) cannot exist.
 */
final readonly class SignatureElement
{
    private function __construct(
        public SignatureElementKind $kind,
        public ?string $keyword,
        public ?SchemaObjectType $targetType,
        /**
         * For a Target element: what the matched object is TO the statement.
         *
         * Declared here because the GRAMMAR is the one place that knows. A foreign key names two
         * tables and only one of them is being altered; nothing downstream can tell them apart,
         * because the classifier sorts targets by name before anyone sees them.
         */
        public TargetRole $targetRole = TargetRole::Subject,
        /**
         * For a BackfillTargets element: the keywords that legitimately END the `SET` clause.
         *
         * Supplied by the driver, because they are engine vocabulary and this class is core. It is
         * also what lets the element DECLINE instead of answering partially: a run that stops at a
         * keyword outside this set stopped inside an expression, not at the end of the clause.
         *
         * @var list<string>
         */
        public array $clauseTerminators = [],
    ) {}

    public static function keyword(string $keyword): self
    {
        return new self(SignatureElementKind::Keyword, mb_strtoupper($keyword), null);
    }

    public static function optionalModifiers(): self
    {
        return new self(SignatureElementKind::OptionalModifiers, null, null);
    }

    /**
     * A target slot.
     *
     * The role is defaulted, so all 81 call sites in the two driver profiles keep their present
     * meaning and only the three foreign-key signatures have anything to say.
     */
    public static function target(SchemaObjectType $type, TargetRole $role = TargetRole::Subject): self
    {
        return new self(SignatureElementKind::Target, null, $type, $role);
    }

    public static function seekKeyword(string $keyword): self
    {
        return new self(SignatureElementKind::SeekKeyword, mb_strtoupper($keyword), null);
    }

    /** A parenthesized identifier list, captured in order. See {@see SignatureElementKind::ColumnList}. */
    public static function columnList(): self
    {
        return new self(SignatureElementKind::ColumnList, null, null);
    }

    /**
     * Every column a `SET` clause assigns to. See {@see SignatureElementKind::BackfillTargets}.
     *
     * @param  list<string>  $clauseTerminators  the keywords that may end the clause, in the
     *                                           engine's own vocabulary — anything else stopping
     *                                           the run means the element declines
     */
    public static function backfillTargets(array $clauseTerminators): self
    {
        return new self(
            SignatureElementKind::BackfillTargets,
            null,
            null,
            clauseTerminators: array_map(mb_strtoupper(...), $clauseTerminators),
        );
    }

    /** Nothing may follow. See {@see SignatureElementKind::EndOfStatement}. */
    public static function endOfStatement(): self
    {
        return new self(SignatureElementKind::EndOfStatement, null, null);
    }
}
