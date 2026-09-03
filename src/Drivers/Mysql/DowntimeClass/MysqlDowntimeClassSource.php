<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\DowntimeClass;

use Closure;
use LogicException;
use Pushery\SQLens\Canonical\CanonicalStatement;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\DowntimeClassMapper;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\DowntimeClassMapping;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\MatrixContext;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\MatrixResolution;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\MatrixResolver;
use Pushery\SQLens\Drivers\Mysql\OnlineDdl\OperationKeyMapper;
use Pushery\SQLens\Engine\ResolvedServerVersion;
use Pushery\SQLens\Exceptions\InvalidRuleEvidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Rules\ServerVersion;

/**
 * The ONE place a MySQL rule gets its `downtime_class`.
 *
 * It builds no classifier of its own. Everything it needs already exists and has an owner: the
 * operation key comes from {@see OperationKeyMapper}, the matrix entry from {@see MatrixResolver},
 * and the entry's four axes become a class through {@see DowntimeClassMapper}. This is the wiring
 * between them, and the reason it is a class rather than three calls repeated per rule: a second
 * copy of that chain is a second answer waiting to disagree with the first.
 *
 * ## Two derivations, both central, neither guessed
 *
 * **A DDL operation gets its class from the matrix, and from nowhere else.** No match is an
 * `undetermined` with a named reason — never a guessed class, and above all never a silent
 * `online`, which is the cheapest possible wrong answer and the one a reader would trust.
 *
 * **A statement that is not DDL has no matrix entry, and never will**: a `WHERE`-less `UPDATE` or
 * an unbatched backfill is not a schema change, so the online-DDL matrix has nothing to say about
 * it. Left there, every lifecycle finding would carry a permanent `undetermined` — or an
 * implementer would hard-code a class and defeat the whole arrangement. So the second derivation
 * is named here, tested here, and is just as central as the first:
 *
 * - a whole-table write (`WHERE`-less or unbatched DML) is `blocking` — its lock reach is the
 *   whole table, whatever the row count turns out to be;
 * - a `TRUNCATE` is `rewrite` — it replaces the table's storage rather than editing rows;
 * - a mixed DML+DDL statement takes the class of the DDL operation involved, because that is what
 *   holds the lock; with no single operation to key on, `blocking`.
 *
 * **A pure convention finding gets NO class at all.** A missing `down()` has no runtime effect to
 * classify, so the field is absent rather than `undetermined`: the class is not unknown here, it
 * is inapplicable, and saying "unknown" would invite someone to go and find it out.
 */
final readonly class MysqlDowntimeClassSource
{
    /**
     * @param  MatrixResolver|null  $matrix  an already-built resolver, for a caller that has one
     * @param  (Closure(): MatrixResolver)|null  $matrixFactory  how to obtain the resolver when none
     *                                                           was given — deferred so the matrix is
     *                                                           read only when a DDL statement
     *                                                           actually needs it, and so a test can
     *                                                           make that read FAIL without deleting
     *                                                           the shipped file out from under the
     *                                                           rest of the suite
     */
    public function __construct(
        private OperationKeyMapper $operationKeys = new OperationKeyMapper,
        private ?MatrixResolver $matrix = null,
        private DowntimeClassMapper $downtimeClasses = new DowntimeClassMapper,
        private ?Closure $matrixFactory = null,
    ) {}

    /**
     * The class for a DDL statement, or a named undetermined.
     *
     * The version is the run's own {@see ResolvedServerVersion} — there is deliberately no second
     * version type here, and no way to pass a bare string: the same pin that every other
     * version-aware decision uses decides this one too.
     */
    public function forDdl(
        CanonicalStatement $statement,
        ResolvedServerVersion $version,
        ?MatrixContext $context = null,
    ): DowntimeClassMapping {
        // A caller that decided nothing about the live table gets the blind context — which is
        // what makes a conditional entry resolve to undetermined rather than to its cheap case.
        $context ??= MatrixContext::blind();

        if (! $version->version instanceof ServerVersion) {
            // The matrix answers per version window, so without a version there is no entry to
            // look up — and the run already knows why it has none.
            return DowntimeClassMapping::undetermined(
                $version->reason ?? UndeterminedReason::UnknownServerVersion,
                'the server version could not be resolved, so no matrix window applies',
            );
        }

        $key = $this->operationKeys->map($statement);

        if (! $key->isResolved()) {
            // Passed through unchanged: the mapper already said, in its own words, why the
            // statement names no single operation. Rewording it here would lose that.
            return DowntimeClassMapping::undetermined($key->reason, $key->detail);
        }

        return $this->forOperation((string) $key->key, $version, $context);
    }

    /**
     * The matrix ENTRY behind an operation, or a named undetermined — the same lookup the class
     * derivation runs on, exposed for the one reader that needs more than a class.
     *
     * A remediation that suggests `ALGORITHM=` and `LOCK=` needs the values the matrix RECORDS, not
     * the class it maps them to. Resolving the matrix a second time in that template would be two
     * lookups that agree until a revision makes them disagree — so it comes through here, and
     * {@see forOperation()} below is now a thin mapping of exactly this result.
     */
    public function resolutionFor(string $operation, ResolvedServerVersion $version, ?MatrixContext $context = null): MatrixResolution
    {
        try {
            $resolver = $this->matrix ?? ($this->matrixFactory ?? MatrixResolver::bundled(...))();
        } catch (InvalidRuleEvidence $failure) {
            // The matrix is DATA, and data can go missing — a configured override path that was
            // deleted, a shipped file a packaging step dropped. Letting the exception escape would
            // take the whole lint run down over one statement; the run instead says what it could
            // not read, which is something a user can act on.
            return MatrixResolution::undetermined(
                UndeterminedReason::OnlineDdlMatrixUnavailable,
                $failure->getMessage(),
            );
        }

        return $resolver->resolve($operation, $version, $context ?? MatrixContext::blind());
    }

    /** One operation through the matrix and the four-axis classifier — the shared lookup. */
    private function forOperation(string $operation, ResolvedServerVersion $version, MatrixContext $context): DowntimeClassMapping
    {
        return $this->downtimeClasses->map($this->resolutionFor($operation, $version, $context));
    }

    /**
     * The class shared by a SET of candidate operations, or a named undetermined when they differ.
     *
     * This exists because MySQL's syntax sometimes hides WHICH operation a statement performs while
     * still settling what it COSTS. `ALTER TABLE t MODIFY col BIGINT NOT NULL` could be a type
     * change, a nullability flip or a reorder — MySQL requires the whole column definition either
     * way, so the statement cannot say. But every one of those operations rebuilds the table, so
     * the CLASS is the same whichever it is, and reporting `undetermined` there would withhold an
     * answer the matrix actually has.
     *
     * The caller names the candidates (a fact about the SQL syntax it is reading); the matrix
     * decides the class. Nothing is hard-coded, and that is the point: if a future matrix revision
     * ever made two candidates disagree, this returns `undetermined` on its own rather than
     * continuing to report the class that used to be shared by all of them.
     *
     * @param  list<string>  $operations  the operations the statement could be performing
     */
    public function forCandidateOperations(
        array $operations,
        ResolvedServerVersion $version,
        ?MatrixContext $context = null,
    ): DowntimeClassMapping {
        if ($operations === []) {
            return DowntimeClassMapping::undetermined(
                UndeterminedReason::OperationKeyUnmapped,
                'no candidate operation was named, so the matrix was never asked',
            );
        }

        $context ??= MatrixContext::blind();
        $shared = null;

        foreach ($operations as $operation) {
            $mapping = $this->forOperation($operation, $version, $context);

            if (! $mapping->isDetermined()) {
                // One unresolved candidate is enough: the shared answer would be a claim about a
                // set this run could not fully evaluate.
                return $mapping;
            }

            if ($shared instanceof DowntimeClass && $shared !== $mapping->downtimeClass) {
                return DowntimeClassMapping::undetermined(
                    UndeterminedReason::OnlineDdlConditionUndecidable,
                    'the operations this statement could be performing do not share one downtime class, and the statement does not say which it is',
                );
            }

            $shared = $mapping->downtimeClass;
        }

        return DowntimeClassMapping::determined($shared ?? throw new LogicException('A determined mapping without a class is unconstructible.'));
    }

    /**
     * The class for a statement the online-DDL matrix does not cover — the second derivation.
     *
     * Not a fallback for a failed matrix lookup: a DDL operation the matrix cannot place stays
     * `undetermined`, and routing it here instead is exactly the silent guess this package
     * refuses. This answers a different question, for statements that are not schema changes at
     * all.
     */
    public function forNonDdl(NonDdlImpact $impact): DowntimeClass
    {
        return $impact->downtimeClass();
    }
}
