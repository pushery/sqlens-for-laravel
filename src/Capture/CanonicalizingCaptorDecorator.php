<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Canonical\CanonicalizationFailure;
use Pushery\SQLens\Canonical\CanonicalizationPipeline;
use Pushery\SQLens\Canonical\Canonicalizer;
use Pushery\SQLens\Canonical\CanonicalStatement;
use Pushery\SQLens\Canonical\Fingerprint;
use Pushery\SQLens\Canonical\RawStatement;
use Pushery\SQLens\Canonical\Stages\StatementSplitter;
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
 * free by being wrapped, with no second canonicalizing path to drift. Both modes
 * hand over each statement the way PDO receives it, so the substitution runs
 * over both alike.
 *
 * One captured entry is not always one statement. `DB::unprepared()` hands the
 * server a whole batch, a trigger with its function or a `.sql` file read in,
 * and both capture modes see it as a single entry. Read as one statement it is
 * classified by its first command, and every later one reaches no rule: a
 * `DROP TABLE` behind a `CREATE INDEX` would pass. So each entry is split here,
 * with the {@see StatementSplitter} every batch in this package goes through,
 * and each statement it holds is canonicalized and judged on its own.
 */
final readonly class CanonicalizingCaptorDecorator implements Captor
{
    public function __construct(
        private Captor $inner,
        private BindingSubstitutor $substitutor,
        private Canonicalizer $canonicalizer,
        private SubjectContext $context,
        private DriverCanonicalization $syntax,
    ) {}

    /**
     * Assemble the decorator for a driver — the substitutor from its binding
     * formatter and its literal syntax, the canonicalizer from the standard pipeline. The one place a
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
            new BindingSubstitutor($formatter, $canonicalization),
            CanonicalizationPipeline::forDriver($canonicalization),
            $context,
            $canonicalization,
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
            $statements = $this->statementsIn($statement);

            if ($statements instanceof SubstitutionFailure) {
                return $this->undetermined($result, $statements->reason, $statements->detail);
            }

            foreach ($statements as [$each, $substituted]) {
                // Numbered as they come: an entry that held three statements moves every later one
                // along, so a sequence stays a statement's place in what the migration runs.
                $rendered = $this->canonicalizeStatement($result, $each->withSequence(count($canonicalized)), $substituted);

                if (! $rendered instanceof CapturedStatement) {
                    return $this->undetermined($result, $rendered);
                }

                $canonicalized[] = $rendered;
            }
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
     * The whole migration as undetermined, for the reason one of its statements could not be rendered,
     * and what this run learned about it when there is something to say.
     */
    private function undetermined(CaptureResult $result, UndeterminedReason $reason, ?string $detail = null): CaptureResult
    {
        return CaptureResult::undetermined(
            $result->file,
            $result->migrationClass,
            $result->section,
            $result->mode,
            $reason,
            annotationClass: $result->annotationClass,
            detail: $detail,
        );
    }

    /**
     * The statements one captured entry hands the server, each beside its text with the bindings
     * inlined, or the reason the entry could not be rendered.
     *
     * An entry the splitter finds one statement in stays the entry it was. One holding several
     * becomes several, each carrying its own text as the raw form: the bindings are inlined by then,
     * and a statement of a batch has no grammar output of its own to keep apart from them.
     *
     * An entry the splitter cannot read stays whole, and the canonicalization decides about it as it
     * decides about any single statement. The splitter is stricter than the canonicalization on one
     * point: it refuses a literal that never closes, where the canonicalization reads it to the end of
     * the statement. Refusing such an entry would turn a migration the canonicalization reads today
     * into an undetermined one. A bound value never leaves a literal open, because the substitutor
     * writes it by the same syntax the splitter reads.
     *
     * @return list<array{CapturedStatement, string}>|SubstitutionFailure
     */
    private function statementsIn(CapturedStatement $statement): array|SubstitutionFailure
    {
        $substituted = $this->substitutor->substitute($statement->rawSql, $statement->bindings);

        if ($substituted instanceof SubstitutionFailure) {
            return $substituted;
        }

        $parts = new StatementSplitter()->split($substituted, $this->syntax);

        if ($parts instanceof CanonicalizationFailure || count($parts) < 2) {
            return [[$statement, $substituted]];
        }

        return array_map(
            static fn (string $part): array => [new CapturedStatement(
                rawSql: $part,
                bindings: [],
                sequence: $statement->sequence,
                direction: $statement->direction,
                withinTransaction: $statement->withinTransaction,
                connectionName: $statement->connectionName,
                driver: $statement->driver,
            ), $part],
            $parts,
        );
    }

    /**
     * Canonicalize one statement from its text with the bindings inlined, returning the enriched
     * statement or the reason it could not be rendered.
     *
     * The text travels beside the statement as a string rather than being read back off its nullable
     * field, so there is never raw grammar output with placeholders in it to fall back to.
     */
    private function canonicalizeStatement(CaptureResult $result, CapturedStatement $statement, string $substituted): CapturedStatement|UndeterminedReason
    {
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
            // The whole canonical form, kind and targets included, so a finding about this statement
            // is told apart from one about another by what the statement is, not by where it sits.
            // The identity variant, so the form version moving does not move the identity with it.
            ->withExcerpt(Fingerprint::forFindingIdentity($canonical))
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
            ? $enriched->withClassification($kind, $canonical->targets, $canonical->keyColumns, $canonical->columnDefinitions, $canonical->actions)
            : $enriched;
    }
}
