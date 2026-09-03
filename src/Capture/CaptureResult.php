<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Capture\PreScan\PreScanHit;
use Pushery\SQLens\Exceptions\UncanonicalizedStatement;
use Pushery\SQLens\Findings\Outcome;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\CaptureMode;
use Pushery\SQLens\Subjects\DownLegDigest;
use Pushery\SQLens\Subjects\DownMethodState;
use Pushery\SQLens\Subjects\MigrationContext;
use Pushery\SQLens\Subjects\MigrationSql;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\SchemaObjectType;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * What a capture produced for ONE migration: its statements, or a named reason
 * why it could not produce them.
 *
 * "No silent green" is cast into the type here exactly as `FindingStatus` casts
 * it for a check: the constructor is private and there is no way to reach the
 * undetermined state without a reason. A migration the capture skipped is never
 * an empty statement list passed off as success — an empty `pass` and a skip are
 * different results, and only one of them is honest.
 */
final readonly class CaptureResult
{
    /**
     * @param  list<CapturedStatement>  $statements
     * @param  list<PreScanHit>  $preScanHits  the static pre-scan hits that made this migration undetermined, in file order — empty for any other result
     * @param  string|null  $annotationClass  the REAL class name of the loaded migration instance — see {@see annotationCarrier()}
     */
    private function __construct(
        public string $file,
        public string $migrationClass,
        public array $statements,
        public CaptureSection $section,
        public CaptureMode $mode,
        public Outcome $outcome,
        public ?UndeterminedReason $reason,
        public ?string $failureDetail = null,
        public array $preScanHits = [],
        public ?string $annotationClass = null,
        /**
         * What the migration's `down()` amounts to, read statically by the pre-scan.
         *
         * Null when no pre-scan ran for this result — which is a different answer from
         * {@see DownMethodState::Missing} and must stay so: "nobody looked" is not "there is
         * none", and a rule may not report the second when only the first is true.
         */
        public ?DownMethodState $downMethodState = null,
        /**
         * The canonical statements this migration's `down()` would emit, or null when the
         * rollback leg was never captured for this result.
         *
         * Attached by the pre-scan gate from a PRETEND capture of the down section — never
         * from an execution, and never in any other mode's own words. See {@see DownLegDigest}.
         */
        public ?DownLegDigest $downLeg = null,
    ) {}

    /**
     * The same result carrying the statements its `down()` would emit.
     *
     * Attached by the pre-scan gate, the one decorator that sits over every capture mode and
     * has already decided this migration is safe to run at all — so a rollback leg is only
     * ever read for a file the gate let through.
     */
    public function withDownLeg(DownLegDigest $downLeg): self
    {
        $clone = clone $this;

        return new self(
            $clone->file,
            $clone->migrationClass,
            $clone->statements,
            $clone->section,
            $clone->mode,
            $clone->outcome,
            $clone->reason,
            $clone->failureDetail,
            $clone->preScanHits,
            $clone->annotationClass,
            $clone->downMethodState,
            $downLeg,
        );
    }

    /**
     * The same result carrying the statically-read state of its `down()`.
     *
     * Attached by the pre-scan gate, which already parsed the file and is the only place that
     * has the answer without a second parse — the pre-scan's whole cost model, and with it the
     * fast path's sub-second promise, rests on parsing each file exactly once.
     */
    public function withDownMethodState(DownMethodState $state): self
    {
        $clone = clone $this;

        return new self(
            $clone->file,
            $clone->migrationClass,
            $clone->statements,
            $clone->section,
            $clone->mode,
            $clone->outcome,
            $clone->reason,
            $clone->failureDetail,
            $clone->preScanHits,
            $clone->annotationClass,
            $state,
            $clone->downLeg,
        );
    }

    /**
     * A migration whose statements were captured. An EMPTY statement list is
     * allowed and means exactly what it says — a migration that emits no SQL
     * (an empty `up()`), which is a real and clean result. What it must never
     * mean is "we could not look"; that is `undetermined`.
     *
     * @param  list<CapturedStatement>  $statements
     */
    public static function captured(
        string $file,
        string $migrationClass,
        array $statements,
        CaptureSection $section,
        CaptureMode $mode,
        ?string $annotationClass = null,
    ): self {
        return new self($file, $migrationClass, $statements, $section, $mode, Outcome::Pass, null, annotationClass: $annotationClass);
    }

    /**
     * A migration the capture attempted and that failed outright — it threw, or
     * the mode could not run it at all. Carries whatever statements were seen
     * before the failure, because they are evidence, and the failure detail (the
     * exception message) so the level-0 capture rule can report WHY without the
     * message having to be re-derived from an exception that no longer exists by
     * the time a rule runs. The detail is kept separate from `reason`, which is
     * the enum for the undetermined axis — a failure is not an undetermined.
     *
     * @param  list<CapturedStatement>  $statements
     */
    public static function failed(
        string $file,
        string $migrationClass,
        array $statements,
        CaptureSection $section,
        CaptureMode $mode,
        ?string $failureDetail = null,
        ?string $annotationClass = null,
    ): self {
        return new self($file, $migrationClass, $statements, $section, $mode, Outcome::Fail, null, $failureDetail, annotationClass: $annotationClass);
    }

    /**
     * The only way to reach the undetermined state — and it requires a reason.
     * No statements are carried: the point of an undetermined capture is that
     * what it would have produced is unknown, and half a sequence read as whole
     * is worse than none.
     *
     * Pre-scan hits ride along ONLY here: a migration the static pre-scan flagged
     * is never captured, so its whole answer is the reasons it was flagged for. A
     * caller that does not pass hits gets the empty default — an undetermined for
     * another reason (an unrepresentable binding, an unreadable file) carries no
     * pre-scan hits, and inventing one would be a false attribution.
     *
     * @param  list<PreScanHit>  $preScanHits  in file order; empty for a non-pre-scan undetermined
     */
    public static function undetermined(
        string $file,
        string $migrationClass,
        CaptureSection $section,
        CaptureMode $mode,
        UndeterminedReason $reason,
        array $preScanHits = [],
        ?string $annotationClass = null,
    ): self {
        return new self($file, $migrationClass, [], $section, $mode, Outcome::Undetermined, $reason, null, $preScanHits, $annotationClass);
    }

    public function isPass(): bool
    {
        return $this->outcome === Outcome::Pass;
    }

    public function isFail(): bool
    {
        return $this->outcome === Outcome::Fail;
    }

    public function isUndetermined(): bool
    {
        return $this->outcome === Outcome::Undetermined;
    }

    /** How many statements this migration produced. */
    public function statementCount(): int
    {
        return count($this->statements);
    }

    /**
     * The subjects the rule engine sees — the one bridge from the capture model
     * into the core model.
     *
     * Only canonicalized statements can become subjects. A statement that never
     * reached the canonicalization layer throws rather than falling back to its
     * raw text: the fallback would be invisible and would leave every rule
     * matching on Laravel's grammar formatting instead of on SQL.
     *
     * @param  list<MigrationStatementDigest>|null  $runStatements  the whole run's statements in
     *                                                              this direction — see
     *                                                              {@see MigrationContext::$runStatements}.
     *                                                              Null is "no run was supplied",
     *                                                              and this result is then its own
     *                                                              run: a caller holding one
     *                                                              migration must not have a rule
     *                                                              reasoning as if it held none.
     * @return list<MigrationSql>
     */
    public function toSubjects(SubjectContext $context, ?array $runStatements = null): array
    {
        // Computed once, from every statement, and shared by all of them: whether a
        // table was created earlier in this migration is a fact about the migration,
        // not about the statement a rule happens to be judging. Building it per
        // statement would be quadratic and, worse, would tempt a rule to reconstruct
        // it from the SQL it can see rather than from the whole migration it cannot.
        $digests = $this->statementDigests();

        $migration = new MigrationContext(
            $this->createdTables(),
            $this->columnsWithNotNullCheck(),
            $this->createdEnumTypes(),
            $this->dropsAConstraint(),
            $digests,
            $this->downMethodState,
            $this->downLeg,
            $runStatements ?? $digests,
        );

        return array_map(
            function (CapturedStatement $statement) use ($context, $migration): MigrationSql {
                $canonical = $statement->canonicalSql
                    ?? throw UncanonicalizedStatement::inMigration($this->migrationClass, $statement->sequence);

                return new MigrationSql(
                    canonicalStatement: $canonical,
                    migrationClass: $this->migrationClass,
                    sourceFile: $this->file,
                    statementIndex: $statement->sequence,
                    direction: $statement->direction,
                    withinTransaction: $statement->withinTransaction,
                    mode: $this->mode,
                    context: $context,
                    annotationClass: $this->annotationClass,
                    statementKind: $statement->statementKind,
                    targets: $statement->targets ?? [],
                    migration: $migration,
                    transactionMode: $statement->transactionMode,
                    keyColumns: $statement->keyColumns,
                    // Derived here, from the bindings the captured statement already carries. No
                    // new plumbing and no byte-range tracking: the fact a secrets rule needs is
                    // whether ANY value came from outside the file, and the empty bindings array is
                    // the positive statement that none did.
                    valueOrigin: ValueOrigin::of($statement->bindings),
                );
            },
            $this->statements,
        );
    }

    /**
     * The canonical qualified names of every table this migration CREATES.
     *
     * Read from the classification, never from the SQL text: a `CREATE TABLE`
     * statement carries its table as a resolved target, so this cannot drift on
     * quoting or `IF NOT EXISTS` the way a string scan would. An unclassified
     * statement contributes nothing — it is not treated as creating some table we
     * could not name.
     *
     * @return list<string>
     */
    private function createdTables(): array
    {
        $created = [];

        foreach ($this->statements as $statement) {
            if ($statement->statementKind !== StatementKind::CreateTable) {
                continue;
            }

            foreach ($statement->targets ?? [] as $target) {
                if ($target->type === SchemaObjectType::Table) {
                    $created[] = $target->qualifiedName();
                }
            }
        }

        return array_values(array_unique($created));
    }

    /**
     * The lowercased column names this migration adds a `CHECK (col IS NOT NULL)` for.
     *
     * This one IS read from the canonical text: the constraint's CHECK expression is not
     * a classified target (the classifier resolves the constrained TABLE, not the column
     * inside an arbitrary boolean expression), so the column is recovered from the
     * normalized form. It is the deliberate safe-pattern marker — a user who wrote this
     * check is applying the pattern that lets a later SET NOT NULL skip its scan.
     *
     * @return list<string>
     */
    private function columnsWithNotNullCheck(): array
    {
        $columns = [];

        foreach ($this->statements as $statement) {
            if ($statement->canonicalSql === null) {
                continue;
            }

            // CHECK ( <col> is not null ) — CHECK is a normalized keyword; the column and
            // `is` are lowercased in the canonical form. Anchored to the not-null shape so
            // an unrelated CHECK never counts.
            if (preg_match('/\bCHECK\s*\(\s*"?([a-z_][a-z0-9_]*)"?\s+is\s+NOT NULL\s*\)/i', $statement->canonicalSql, $matches) === 1) {
                $columns[] = strtolower($matches[1]);
            }
        }

        return array_values(array_unique($columns));
    }

    /**
     * The lowercased names of enum types this migration creates (`CREATE TYPE … AS ENUM`).
     *
     * Read from the canonical text, like the not-null checks: `CREATE TYPE` is not a
     * classified statement kind, so the type name is recovered from the normalized form.
     *
     * @return list<string>
     */
    private function createdEnumTypes(): array
    {
        $types = [];

        foreach ($this->statements as $statement) {
            if ($statement->canonicalSql === null) {
                continue;
            }

            if (preg_match('/\bCREATE TYPE\s+"?([a-z_][a-z0-9_.]*)"?\s+AS\s+enum\b/i', $statement->canonicalSql, $matches) === 1) {
                $types[] = strtolower($matches[1]);
            }
        }

        return array_values(array_unique($types));
    }

    /**
     * Whether the migration drops any constraint — read from the classification
     * ({@see StatementKind::DropConstraint}), not the SQL text. It is the signal that
     * tells Laravel's enum() CHANGE (a drop then an add of a CHECK) apart from a
     * first-time enum column (only an add).
     */
    private function dropsAConstraint(): bool
    {
        return array_any($this->statements, fn (CapturedStatement $statement): bool => $statement->statementKind === StatementKind::DropConstraint);
    }

    /**
     * This result read as another migration's ROLLBACK leg — the shape a rule sees when it
     * asks what `down()` would emit.
     *
     * The conversion lives here rather than on {@see DownLegDigest} so the dependency keeps
     * pointing one way: the capture layer knows the subject model, the subject model knows
     * nothing about captures.
     *
     * Two things make a leg unreadable, and both would otherwise read as "the rollback
     * destroys nothing": a result that is undetermined (nothing was captured, for a named
     * reason), and one holding a statement that never reached canonicalization — a rollback
     * statement SQLens cannot parse is precisely the one it must not vouch for.
     */
    public function asDownLeg(): DownLegDigest
    {
        if ($this->reason instanceof UndeterminedReason) {
            return DownLegDigest::unreadable($this->reason);
        }

        if (array_any($this->statements, static fn (CapturedStatement $statement): bool => $statement->canonicalSql === null)) {
            return DownLegDigest::unreadable(UndeterminedReason::UncanonicalizableStatement);
        }

        return DownLegDigest::of($this->statementDigests());
    }

    /**
     * The migration's statements as an ordered stream of canonical digests — the
     * order-sensitive material a rule needs when a distilled boolean cannot answer its
     * question. Built in capture order from the same statements that become subjects,
     * and carrying only what a rule may see: the canonical string, the classification,
     * the transaction context, and the statement's own index.
     *
     * A statement that never reached canonicalization is skipped rather than carried
     * with an empty string — it is about to throw in {@see toSubjects()} anyway, and a
     * blank entry in the stream would be a phantom neighbor a rule could miscount.
     *
     * Public because a RUN is assembled from these — {@see CaptureRun::statementDigestsBySection()}
     * concatenates them so a rule reasoning about the absence of an index can look past the one
     * file it is judging. Built the same way for both, from one method, so the per-migration stream
     * and the run-wide one can never be two different readings of the same statements.
     *
     * @return list<MigrationStatementDigest>
     */
    public function statementDigests(): array
    {
        $digests = [];

        foreach ($this->statements as $statement) {
            if ($statement->canonicalSql === null) {
                continue;
            }

            $digests[] = new MigrationStatementDigest(
                $statement->sequence,
                $statement->statementKind,
                $statement->canonicalSql,
                $statement->withinTransaction,
                $statement->targets ?? [],
                $statement->transactionMode,
                $statement->keyColumns,
            );
        }

        return $digests;
    }

    /**
     * The migration as a carrier for its CLASS-level `#[SqlensIgnore]` annotations,
     * independent of its statements. The annotation suppression layer reads the
     * attribute off the migration class by reflection, so it needs a subject even for
     * a result that produced no statements (a NOT_CAPTURABLE fail, an undetermined
     * skip). The canonical statement is empty and the index is zero — this subject is
     * never fed to a SQL rule, only used to reach the class the finding came from.
     *
     * `annotationClass` is what makes that reachable. `migrationClass` is the
     * migration NAME (the file basename, which is what the repository records and what
     * a report shows) — and for Laravel's anonymous migrations that name is not a
     * class at all, so reflecting it finds nothing. The captor therefore records the
     * real class of the instance it loaded, and that is what carries the attribute.
     */
    public function annotationCarrier(SubjectContext $context): MigrationSql
    {
        return new MigrationSql(
            canonicalStatement: '',
            migrationClass: $this->migrationClass,
            sourceFile: $this->file,
            statementIndex: 0,
            direction: $this->section->direction(),
            withinTransaction: false,
            mode: $this->mode,
            context: $context,
            annotationClass: $this->annotationClass,
        );
    }

    /**
     * A deterministic array projection with a fixed key order.
     *
     * @return array{file: string, migration_class: string, section: string, mode: string, outcome: string, reason: string|null, failure_detail: string|null, prescan_hits: list<array{rule_id: string, file: string, line: int, target: string, reason: string}>, statements: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'file' => $this->file,
            'migration_class' => $this->migrationClass,
            'section' => $this->section->value,
            'mode' => $this->mode->value,
            'outcome' => $this->outcome->value,
            'reason' => $this->reason?->value,
            'failure_detail' => $this->failureDetail,
            'prescan_hits' => array_map(
                static fn (PreScanHit $hit): array => $hit->toArray(),
                $this->preScanHits,
            ),
            'statements' => array_map(
                static fn (CapturedStatement $statement): array => $statement->toArray(),
                $this->statements,
            ),
        ];
    }
}
