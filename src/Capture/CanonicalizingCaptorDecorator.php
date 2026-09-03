<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Canonical\CanonicalizationPipeline;
use Pushery\SQLens\Canonical\Canonicalizer;
use Pushery\SQLens\Canonical\CanonicalStatement;
use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementOrigin;
use Pushery\SQLens\Contracts\BindingFormatter;
use Pushery\SQLens\Contracts\Captor;
use Pushery\SQLens\Contracts\DriverCanonicalization;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * Wraps a captor so that every statement it produces reaches a rule ONLY in
 * canonical form — bindings inlined, then run through the canonicalization
 * pipeline — and no rule ever sees raw grammar output.
 *
 * This is the structural enforcement of "rules never regex on grammar quirks"
 * (pitfall 6). The capture-result model already makes a `MigrationSql` subject
 * unbuildable without a canonical form; this decorator is what fills that form,
 * so the two together mean a run either has canonical SQL for a statement or the
 * migration is honestly `undetermined` — there is no third state where a rule
 * quietly matches on `values (1)` spacing.
 *
 * Determinism lives here too: the substitution renders values locale- and
 * engine-independently, and the canonicalization collapses the formatting the
 * grammar happened to emit. Same migration, same driver ⇒ same canonical SQL, on
 * a dev Mac and in CI.
 *
 * It decorates rather than replaces: the inner captor (pretend today, shadow
 * later) owns HOW the SQL is obtained; this owns turning what it obtained into
 * the one form the rules read. A second capture mode gets canonicalization for
 * free by being wrapped, with no second canonicalizing path to drift.
 */
final readonly class CanonicalizingCaptorDecorator implements Captor
{
    public function __construct(
        private Captor $inner,
        private BindingSubstitutor $substitutor,
        private Canonicalizer $canonicalizer,
        private SubjectContext $context,
    ) {}

    /**
     * Assemble the decorator for a driver — the substitutor from its binding
     * formatter, the canonicalizer from the standard pipeline. The one place a
     * caller wires capture to canonicalization, so the pipeline order is never
     * re-listed here.
     *
     * The context carries the run's driver, profile and strictness for the
     * pipeline. Its driver must be the one the canonicalization describes — a
     * mismatch would canonicalize with one engine's rules under another's label —
     * so the caller resolves both from the same driver.
     */
    public static function forDriver(
        Captor $inner,
        DriverCanonicalization $canonicalization,
        BindingFormatter $formatter,
        SubjectContext $context,
    ): self {
        return new self(
            $inner,
            new BindingSubstitutor($formatter),
            CanonicalizationPipeline::forDriver($canonicalization),
            $context,
        );
    }

    public function capture(iterable $migrations, CaptureSection $section): CaptureRun
    {
        $run = $this->inner->capture($migrations, $section);

        return CaptureRun::of(
            array_map($this->canonicalizeResult(...), $run->results),
            $run->mode,
        );
    }

    public function mode(): CaptureMode
    {
        return $this->inner->mode();
    }

    /**
     * Canonicalize every statement of a captured result. A result that is not a
     * clean capture (a migration that threw, or one already undetermined) passes
     * through untouched — its statements are evidence, not rule inputs, and there
     * is nothing to canonicalize into a subject.
     *
     * If any statement of a captured result cannot be rendered — an
     * unrepresentable binding, an unbalanced placeholder count, a statement the
     * pipeline rejects — the WHOLE migration becomes undetermined with the named
     * reason. A partial canonical sequence read as whole is worse than none: a
     * rule would conclude from statements the migration does not actually run.
     */
    private function canonicalizeResult(CaptureResult $result): CaptureResult
    {
        if (! $result->isPass()) {
            return $result;
        }

        $canonicalized = [];

        foreach ($result->statements as $statement) {
            $rendered = $this->canonicalizeStatement($result, $statement);

            if (! $rendered instanceof CapturedStatement) {
                return CaptureResult::undetermined(
                    $result->file,
                    $result->migrationClass,
                    $result->section,
                    $result->mode,
                    $rendered,
                    annotationClass: $result->annotationClass,
                );
            }

            $canonicalized[] = $rendered;
        }

        // The annotation carrier is carried THROUGH: this decorator rewrites the
        // statements, not which migration they came from. Dropping it here would make
        // a class-level suppression a silent no-op on every canonicalized run — the
        // whole point of threading it.
        return CaptureResult::captured(
            $result->file,
            $result->migrationClass,
            $canonicalized,
            $result->section,
            $result->mode,
            $result->annotationClass,
        );
    }

    /**
     * Substitute and canonicalize one statement, returning the enriched statement
     * or the reason it could not be rendered.
     */
    private function canonicalizeStatement(CaptureResult $result, CapturedStatement $statement): CapturedStatement|UndeterminedReason
    {
        $substituted = $this->substitutor->substitute($statement->rawSql, $statement->bindings);

        if ($substituted instanceof SubstitutionFailure) {
            return $substituted->reason;
        }

        $raw = new RawStatement(
            sql: $substituted,
            origin: new StatementOrigin(
                file: $result->file,
                migrationClass: $result->migrationClass,
                statementIndex: $statement->sequence,
                direction: $statement->direction,
            ),
            withinTransaction: $statement->withinTransaction,
        );

        $canonical = $this->canonicalizer->canonicalizeRaw($raw, $this->context);

        if (! $canonical instanceof CanonicalStatement) {
            return UndeterminedReason::UncanonicalizableStatement;
        }

        $enriched = $statement
            ->withSubstitutedSql($substituted)
            ->withCanonicalSql($canonical->canonicalSql)
            // The RESOLVED transaction mode, not the migrator flag it started from. The
            // resolver can land on Undetermined — an explicit transaction opening inside
            // the migrator's, an unbalanced marker — and a lock-hygiene rule that only
            // ever saw the boolean read that as "not in a transaction" and said nothing.
            ->withTransactionMode($canonical->transaction->mode);

        // The classification rides along when the driver produced one, so a
        // migration-level rule can ask what a statement acts on without re-parsing
        // its SQL. A statement the driver left unclassified keeps null and reaches a
        // rule unclassified — never mislabeled to make it look handled.
        $kind = $canonical->statementKind;

        return $kind instanceof StatementKind && $canonical->targets !== null
            ? $enriched->withClassification($kind, $canonical->targets, $canonical->keyColumns)
            : $enriched;
    }
}
