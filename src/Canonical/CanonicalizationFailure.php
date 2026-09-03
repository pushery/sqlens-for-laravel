<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * A named canonicalization failure — the "no silent green" of this layer. It
 * carries the reason and a short English detail; the generic constructor is
 * private so a failure can only be built through a named factory that supplies
 * the reason.
 *
 * Where the failure is anchored to a position in the input batch (an unterminated
 * literal, a malformed delimiter), the 0-based `offset` records where the failing
 * construct began, so a caller that knows the batch can report a line. It is null
 * for failures with no meaningful position (a driver that declares no split syntax,
 * a stage that returned the wrong shape).
 */
final readonly class CanonicalizationFailure
{
    private function __construct(
        public CanonicalizationFailureReason $reason,
        public string $detail,
        public ?int $offset = null,
    ) {}

    public static function emptyStatement(StatementOrigin $origin): self
    {
        return new self(
            CanonicalizationFailureReason::EmptyStatement,
            sprintf('empty statement at %s:%d', $origin->file, $origin->statementIndex),
        );
    }

    public static function invalidStageResult(string $stageClass): self
    {
        return new self(
            CanonicalizationFailureReason::InvalidStageResult,
            sprintf('stage %s returned neither a RawStatement nor a CanonicalStatement', $stageClass),
        );
    }

    public static function unknownCanonicalFormVersion(int $version): self
    {
        return new self(
            CanonicalizationFailureReason::UnknownCanonicalFormVersion,
            sprintf('canonical form version %d is not readable by this build', $version),
        );
    }

    public static function unterminatedLiteral(string $what, ?int $offset = null): self
    {
        return new self(
            CanonicalizationFailureReason::UnterminatedLiteral,
            sprintf('unterminated %s in the statement batch', $what),
            $offset,
        );
    }

    public static function unknownDelimiterSituation(string $detail, ?int $offset = null): self
    {
        return new self(
            CanonicalizationFailureReason::UnknownDelimiterSituation,
            $detail,
            $offset,
        );
    }

    public static function missingSplitSyntax(): self
    {
        return new self(
            CanonicalizationFailureReason::MissingSplitSyntax,
            'the driver declares no literal or comment syntax; the batch cannot be split safely',
        );
    }

    public static function tooManyQualificationLevels(string $reference, int $levels): self
    {
        return new self(
            CanonicalizationFailureReason::TooManyQualificationLevels,
            sprintf('the identifier "%s" has %d qualification levels; a schema.name reference holds at most two', $reference, $levels),
        );
    }

    public static function missingCanonicalArtifact(string $artifact): self
    {
        return new self(
            CanonicalizationFailureReason::MissingCanonicalArtifact,
            sprintf('the driver did not supply the %s this canonicalization stage needs', $artifact),
        );
    }

    public static function unrecognizedStatementForm(string $lead): self
    {
        return new self(
            CanonicalizationFailureReason::UnrecognizedStatementForm,
            sprintf('the statement leading with "%s" matches no known shape for the driver', $lead),
        );
    }

    public static function ambiguousTarget(string $detail): self
    {
        return new self(
            CanonicalizationFailureReason::AmbiguousTarget,
            $detail,
        );
    }
}
