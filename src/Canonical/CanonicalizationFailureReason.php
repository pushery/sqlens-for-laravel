<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

/**
 * Why canonicalization could not produce a canonical statement — a named reason,
 * so a caller (the lint suite) can turn it into an undetermined finding
 * instead of swallowing a raw string. Every failure of the layer is one of these.
 */
enum CanonicalizationFailureReason: string
{
    /** The captured statement is empty — there is nothing to canonicalize. */
    case EmptyStatement = 'empty_statement';

    /** A stage returned neither a RawStatement nor a CanonicalStatement — a contract violation. */
    case InvalidStageResult = 'invalid_stage_result';

    /** The input artifact carries a canonical-form version this build cannot read. */
    case UnknownCanonicalFormVersion = 'unknown_canonical_form_version';

    /** A string literal (or quoted identifier, comment, dollar-quoted body) is never closed. */
    case UnterminatedLiteral = 'unterminated_literal';

    /** A DELIMITER redefinition is malformed — the splitter cannot tell where a statement ends. */
    case UnknownDelimiterSituation = 'unknown_delimiter_situation';

    /** The driver declares no literal or comment syntax, so the batch cannot be split safely. */
    case MissingSplitSyntax = 'missing_split_syntax';

    /** An identifier reference carries more qualification levels than a schema.name reference can hold. */
    case TooManyQualificationLevels = 'too_many_qualification_levels';

    /** The driver did not supply a canonicalization artifact a stage needs (e.g. an identifier quoting character). */
    case MissingCanonicalArtifact = 'missing_canonical_artifact';

    /** The statement matches no known shape for the driver — its kind cannot be decided (never guessed as ddl_other). */
    case UnrecognizedStatementForm = 'unrecognized_statement_form';

    /** A recognized statement shape has a target that is not a resolvable identifier (a dynamically composed name). */
    case AmbiguousTarget = 'ambiguous_target';
}
