<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical;

use Pushery\SQLens\Contracts\CanonicalizationStage;
use Pushery\SQLens\Subjects\MigrationSql;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The pipeline orchestrator: it runs the declared stages in order over a captured
 * migration statement and produces a CanonicalStatement, or a named
 * CanonicalizationFailure when it cannot. It touches no database — every input
 * arrives through the subject and the injected context.
 *
 * Three-valued by construction: an empty statement, a stage that breaks its
 * contract, or an input artifact of an unknown canonical-form version each yield
 * a named failure, never a silently passed-through raw string.
 */
final readonly class Canonicalizer
{
    /**
     * @param  list<CanonicalizationStage>  $stages  in declared execution order
     */
    public function __construct(private array $stages) {}

    /**
     * Canonicalize a captured migration statement. A stage may finalize early by
     * returning a CanonicalStatement; otherwise the refined statement is finalized
     * here as an as-yet-unclassified canonical statement.
     */
    public function canonicalize(MigrationSql $subject): CanonicalStatement|CanonicalizationFailure
    {
        return $this->canonicalizeRaw(RawStatement::fromSubject($subject), $subject->context());
    }

    /**
     * Canonicalize a raw statement the capture layer built directly from its
     * substituted SQL, without first wrapping it in a subject.
     *
     * The capture path reaches the pipeline this way: it has one substituted
     * statement plus its provenance, not a rule subject (the subject is the
     * OUTPUT of canonicalization, so it cannot be the input). Both entry points
     * run the identical pipeline — there is no second canonicalization path that
     * could drift from this one.
     */
    public function canonicalizeRaw(RawStatement $statement, SubjectContext $context): CanonicalStatement|CanonicalizationFailure
    {
        if (trim($statement->sql) === '') {
            return CanonicalizationFailure::emptyStatement($statement->origin);
        }

        $current = $statement;

        foreach ($this->stages as $stage) {
            $result = $stage($current, $context);

            if ($result instanceof CanonicalStatement) {
                return $result;
            }

            if ($result instanceof RawStatement) {
                $current = $result;

                continue;
            }

            // A stage may abort the pipeline with a named domain failure — an
            // unterminated quote, an over-qualified identifier, a driver missing a
            // required artifact — which is propagated verbatim so the reason
            // survives. Anything else is a contract violation.
            if ($result instanceof CanonicalizationFailure) {
                return $result;
            }

            return CanonicalizationFailure::invalidStageResult($stage::class);
        }

        return new CanonicalStatement(
            canonicalSql: $current->sql,
            origin: $current->origin,
            transaction: $current->transaction ?? TransactionContext::fromMigratorFlag($current->withinTransaction),
            formVersion: CanonicalFormVersion::current(),
        );
    }

    /**
     * Validate a stored canonical statement before reading it: an artifact whose
     * canonical-form version this build does not know is a named failure, never
     * silently trusted. This is the path a later drift comparison uses when it
     * reads a canonical artifact from an earlier run.
     */
    public function ensureReadable(CanonicalStatement $stored): CanonicalStatement|CanonicalizationFailure
    {
        if (! $stored->formVersion->isKnown()) {
            return CanonicalizationFailure::unknownCanonicalFormVersion($stored->formVersion->version);
        }

        return $stored;
    }
}
