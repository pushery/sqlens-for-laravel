<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * One normalization stage in the canonicalization pipeline. It receives the
 * in-flight RawStatement and the injected context, and MUST return one of:
 *   - a refined RawStatement, to continue the pipeline;
 *   - a CanonicalStatement, to finalize it early; or
 *   - a CanonicalStatement is not the only terminal — a CanonicalizationFailure
 *     aborts the pipeline with a named, three-valued reason (an unterminated
 *     quote, an over-qualified identifier, a driver missing a required artifact),
 *     which the Canonicalizer propagates verbatim.
 *
 * The return is `mixed` on purpose — the Canonicalizer validates it at runtime:
 * a stage that returns anything other than those three is a contract violation
 * reported as an undetermined InvalidStageResult (itself a named, first-class
 * failure, never a silently passed-through raw string). That is exactly why the
 * return is not statically constrained to the union: the defensive path has to be
 * reachable and testable. Driver-specific stages plug in through the driver
 * extension point; a stage never touches a database.
 */
interface CanonicalizationStage
{
    public function __invoke(RawStatement $statement, SubjectContext $context): mixed;
}
