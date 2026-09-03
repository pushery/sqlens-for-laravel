<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Remediation;

use Pushery\SQLens\Drivers\Mysql\OnlineDdl\MatrixEntry;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;

/**
 * The raw statement Laravel's grammar cannot emit — with the two values read out of the online-DDL
 * matrix rather than chosen here.
 *
 * ## What the clause actually buys, and why saying it wrong would be worse than silence
 *
 * `ALGORITHM=INPLACE` does not make a copying operation online. **It makes the server refuse.** An
 * operation MySQL can only perform by copying fails with an error instead of quietly copying the
 * table, so the deploy stops before it locks anything rather than in the middle of it.
 *
 * A payload that presented the clause as a way to make the change cheap would leave somebody more
 * confident and no safer — which is the single most expensive thing a fix template can do. So the
 * gate that follows the statement is about the REFUSAL, not about a fallback.
 *
 * ## The values come from the matrix or the payload does not exist
 *
 * `algorithm` and `lock` are read off the resolved {@see MatrixEntry}. A guessed `ALGORITHM` would
 * be worse than none: pinning `INPLACE` on an operation that cannot do it turns a slow deploy into
 * a failed one, and pinning `COPY` on one that could have been instant buys a rewrite nobody
 * needed. When the matrix cannot place the operation, the rule hands over nothing at all — the
 * finding still says what it saw, and the absence of a suggestion is the honest answer rather than
 * a silent one.
 *
 * ## `LOCK=NONE` is not offered where it would mean nothing
 *
 * A handful of statements accept the clause and ignore it — `EXCHANGE PARTITION` takes even
 * `ALGORITHM=COPY, LOCK=NONE`, a self-contradictory pair every other statement rejects. The matrix
 * records that, {@see MatrixEntry::clauseIsMeaningful()} reports it, and this template declines
 * those: a clause that parses and guarantees nothing is exactly the silent green the package exists
 * to catch.
 *
 * Every question about the matrix is asked of the ENTRY rather than of its axes, and that placement
 * is enforced: a MySQL file outside `OnlineDdl/` that evaluated an axis would be a second, drifting
 * decision table, and the classifier's own guard refuses one.
 *
 * ## No OSC tool, deliberately
 *
 * Zero-downtime execution through `gh-ost` or `pt-online-schema-change` is a stated non-goal. This
 * package describes SQL and never orchestrates a tool that rewrites tables on somebody's behalf, so
 * no step here names one. That such tools exist belongs in documentation, not in a payload an agent
 * might act on.
 *
 * ## It renders; it never runs
 */
final readonly class AlgorithmLockTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.algorithm_lock.';

    /** The shipped evidence register — a rule class must not name it, so the lookup lives here. */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The pinned statement for THIS matrix entry, or null when the entry names no clause to pin.
     *
     * @param  array<string, string>  $context  the table, when the statement named one
     */
    public function forEntry(MatrixEntry $entry, array $context, string $ruleId, ?DowntimeClass $downtimeClass): ?RemediationPayload
    {
        // The clause is meaningless for this operation — it either does not parse or parses and is
        // ignored. Suggesting it would hand somebody a guarantee the server never makes. The
        // question is asked of the ENTRY rather than of its axes: reading those here would be a
        // second decision table, and the classifier's own guard refuses one.
        if (! $entry->clauseIsMeaningful()) {
            return null;
        }

        $filled = [...$context, 'algorithm' => $entry->algorithmClause(), 'lock' => $entry->lockClause()];

        return new RemediationPayload(
            steps: array_map(
                static fn (RemediationStep $step): RemediationStep => $step->filled($filled),
                [
                    new RemediationStep(
                        order: 1,
                        kind: RemediationStepKind::MigrationStatement,
                        noteKey: self::LANG.'pin_the_clause',
                        sqlTemplate: 'ALTER TABLE {{table}} {{operation}}, ALGORITHM={{algorithm}}, LOCK={{lock}}',
                        laravelSnippet: "// the builder cannot emit these two clauses — say why here\nDB::statement('ALTER TABLE {{table}} {{operation}}, ALGORITHM={{algorithm}}, LOCK={{lock}}');",
                    ),
                    new RemediationStep(
                        order: 2,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: self::LANG.'expect_a_refusal',
                    ),
                    new RemediationStep(
                        order: 3,
                        kind: RemediationStepKind::ManualGate,
                        noteKey: $this->windowNoteKey($entry),
                    ),
                ],
            ),
            strategy: RemediationStrategy::AlgorithmLockHint,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.raw_sql_is_an_exception',
                self::LANG.'precondition.version_matches_the_entry',
            ],
            verification: self::LANG.'verification',
            references: array_map(
                static fn (RuleEvidenceEntry $reference): string => $reference->url,
                $this->evidence->for($ruleId),
            ),
        );
    }

    /**
     * Which closing note this operation gets — the FACT comes from the entry, the ADVICE is here.
     *
     * An operation that rewrites the table needs a window whatever clause is pinned on it: the
     * clause makes the server refuse, it does not make the rewrite cheap. Written on one line
     * rather than as a multi-line ternary, which xdebug records as two statements it can never
     * attribute an execution to — an unhittable line is a coverage gate nobody can pass honestly.
     */
    private function windowNoteKey(MatrixEntry $entry): string
    {
        return $entry->rewritesTheTable() ? self::LANG.'plan_a_window' : self::LANG.'no_window_needed';
    }
}
