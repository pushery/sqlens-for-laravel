<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Remediation;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Rules\RuleEvidence;
use Pushery\SQLens\Rules\RuleEvidenceEntry;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The safe sequence behind `CREATE INDEX CONCURRENTLY` and `DROP INDEX CONCURRENTLY` — the fix for
 * the two PostgreSQL rules that flag an index operation taking a lock the whole table waits behind.
 *
 * ## Why this is four steps and not one
 *
 * "Add CONCURRENTLY" is the advice everybody already knows, and it is the advice that fails. The
 * keyword changes how the statement must be RUN, and a migration that only gains the keyword dies
 * on its first deploy with `CREATE INDEX CONCURRENTLY cannot run inside a transaction block` —
 * Laravel wraps `up()` in one by default. So the sequence carries the statement AND its habitat:
 * the migration it needs (`$withinTransaction = false`), and the cleanup for the state a failed
 * attempt leaves behind.
 *
 * ## The step nobody expects, and the reason step one is a reference rather than a copy
 *
 * A concurrent build waits for existing transactions, so a run under a `lock_timeout` can be
 * aborted — and PostgreSQL then leaves an INVALID index sitting under the name it was building.
 * The name is taken, so the obvious response, re-running the migration, fails on a name conflict
 * and reads like a broken fix rather than like leftover state. That is why the timeout preamble is
 * step one and the INVALID sweep is step four: they are the two ends of the same fact, and a
 * sequence naming only the first hands somebody a trap.
 *
 * Step one REFERENCES the timeout preamble instead of restating its statements. The preamble is its
 * own template with its own values, and two copies of a session preamble would drift the day one of
 * them was tuned — with the halves each looking correct on their own.
 *
 * ## Everything is read from the CANONICAL view
 *
 * The index name, the table and the key columns come from the classified statement — `soleTarget()`
 * and `keyColumns` — never from the SQL text and never generated. Generating an index name would
 * make two runs over the same migration produce two different payloads, which is the determinism
 * this package holds everywhere else; and a name invented here would not be the name the failed
 * attempt left behind, which is exactly the name step four has to drop.
 *
 * A fact the statement does not carry leaves its placeholder STANDING rather than blank
 * ({@see RemediationStep::filled()}): a `DROP INDEX` names no table, and a template that quietly
 * lost one would read as a complete statement about the wrong object.
 *
 * ## It renders; it never runs
 *
 * Nothing here executes anything. The payload is material an agent applies and a later `sqlens:lint`
 * re-checks — that verification, not this class, is what says the fix worked.
 */
final readonly class ConcurrentlyTemplate
{
    /** The key prefix every note, precondition and verification string of this template lives under. */
    private const string LANG = 'sqlens::messages.remediation.concurrently.';

    /**
     * The shipped evidence register, which is where this template's references come from.
     *
     * Not a URL constant in this file, and the reason is not only that a foreign endpoint literal
     * in `src/` is refused by the no-implicit-network guard. The register ALREADY holds the
     * PostgreSQL anchor for each of these rules, because a safety rule has to be able to answer
     * "why is this dangerous" — so writing the address a second time here would create a copy that
     * can disagree with the rule's own citation, in whichever direction nobody is reading.
     *
     * Resolved once per instance, the same way {@see RuleDriverNotes} is on the rule base: an
     * optional dependency for a test to substitute, and the bundled register otherwise.
     */
    private RuleEvidence $evidence;

    public function __construct(?RuleEvidence $evidence = null)
    {
        $this->evidence = $evidence ?? RuleEvidence::bundled();
    }

    /**
     * The sequence for a `CREATE INDEX` that should have been concurrent.
     *
     * @param  string  $ruleId  the rule this fixes, carried so a payload lifted out of a finding
     *                          still says what it is about
     */
    public function forCreateIndex(MigrationStatementView $statement, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: $this->fill([
                $this->timeoutPreamble(),
                $this->separateMigration(),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::MigrationStatement,
                    noteKey: self::LANG.'create_index',
                    sqlTemplate: 'CREATE INDEX CONCURRENTLY {{index}} ON {{table}} ({{columns}})',
                    withinTransaction: false,
                ),
                new RemediationStep(
                    order: 4,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'sweep_invalid',
                    sqlTemplate: 'DROP INDEX CONCURRENTLY {{index}}',
                    withinTransaction: false,
                ),
            ], $statement),
            strategy: RemediationStrategy::Concurrently,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.no_leftover_index',
                self::LANG.'precondition.migrator_leaves_transaction',
            ],
            verification: self::LANG.'verification',
            references: $this->references($ruleId),
        );
    }

    /**
     * The sequence for a `DROP INDEX` that should have been concurrent.
     *
     * The same shape and deliberately not the same steps. A concurrent drop that is interrupted
     * leaves the index behind marked dead rather than leaving a half-built one, so the cleanup is
     * to run the drop again — and a template that reused the create-side sweep would tell somebody
     * to drop an index the failure never created.
     */
    public function forDropIndex(MigrationStatementView $statement, string $ruleId, DowntimeClass $downtimeClass): RemediationPayload
    {
        return new RemediationPayload(
            steps: $this->fill([
                $this->timeoutPreamble(),
                $this->separateMigration(),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::MigrationStatement,
                    noteKey: self::LANG.'drop_index',
                    sqlTemplate: 'DROP INDEX CONCURRENTLY {{index}}',
                    withinTransaction: false,
                ),
                new RemediationStep(
                    order: 4,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: self::LANG.'retry_drop',
                    sqlTemplate: 'DROP INDEX CONCURRENTLY IF EXISTS {{index}}',
                    withinTransaction: false,
                ),
            ], $statement),
            strategy: RemediationStrategy::Concurrently,
            ruleId: $ruleId,
            downtimeClass: $downtimeClass,
            preconditions: [
                self::LANG.'precondition.index_unused',
                self::LANG.'precondition.migrator_leaves_transaction',
            ],
            verification: self::LANG.'verification',
            references: $this->references($ruleId),
        );
    }

    /**
     * Step one: bound the wait before the statement that waits.
     *
     * It carries no SQL of its own on purpose — the values belong to the timeout-preamble template,
     * and restating them here would be a second copy to keep in step. The note is where the
     * non-obvious part lives: a timeout that fires DURING a concurrent build is what produces the
     * INVALID index step four sweeps up.
     */
    private function timeoutPreamble(): RemediationStep
    {
        return new RemediationStep(
            order: 1,
            kind: RemediationStepKind::SessionSetting,
            noteKey: self::LANG.'timeout_preamble',
            withinTransaction: false,
        );
    }

    /**
     * Step two: the migration the statement needs, which is the step the obvious fix omits.
     *
     * `$withinTransaction = false` is the load-bearing line of the whole sequence. Laravel wraps
     * `up()` in a transaction on PostgreSQL, and `CONCURRENTLY` refuses to run inside one — so a
     * migration that gained only the keyword fails on its first deploy, in production, at the point
     * where somebody believed the problem was already solved.
     */
    private function separateMigration(): RemediationStep
    {
        return new RemediationStep(
            order: 2,
            kind: RemediationStepKind::SeparateMigration,
            noteKey: self::LANG.'separate_migration',
            laravelSnippet: 'public $withinTransaction = false;',
            withinTransaction: false,
        );
    }

    /**
     * The addresses behind this rule's advice, read from the register rather than restated.
     *
     * A rule with no entry yields no references, which is honest rather than convenient: the
     * completeness guard over the register is what makes an evidence-free safety rule a failure,
     * and inventing a link here would hide exactly the gap that guard exists to show.
     *
     * @return list<string>
     */
    private function references(string $ruleId): array
    {
        return array_map(
            static fn (RuleEvidenceEntry $entry): string => $entry->url,
            $this->evidence->for($ruleId),
        );
    }

    /**
     * Every step with its placeholders filled from the classified statement.
     *
     * @param  list<RemediationStep>  $steps
     * @return list<RemediationStep>
     */
    private function fill(array $steps, MigrationStatementView $statement): array
    {
        $context = $this->context($statement);

        return array_map(static fn (RemediationStep $step): RemediationStep => $step->filled($context), $steps);
    }

    /**
     * The placeholder values THIS statement carries — and only the ones it carries.
     *
     * A key is absent rather than empty when the statement does not name the fact: an absent key
     * leaves `{{table}}` visible in the rendered SQL, which reads as a hole somebody must fill,
     * while an empty string would render `ON ()` and read as a finished statement.
     *
     * @return array<string, string>
     */
    private function context(MigrationStatementView $statement): array
    {
        $context = [];

        $index = $statement->soleTarget(SchemaObjectType::Index);

        if ($index instanceof StatementTarget) {
            $context['index'] = $index->qualifiedName();
        }

        $table = $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        if ($statement->keyColumns !== []) {
            $context['columns'] = implode(', ', $statement->keyColumns);
        }

        return $context;
    }
}
