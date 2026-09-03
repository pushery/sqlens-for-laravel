<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L4;

use Override;
use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Deploy\Contracts\ProducesDebt;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\ExpandContractTemplate;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\MigrationStatementDigest;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * The expand half of an expand/contract deploy, with the contract half nowhere in the run.
 *
 * A column is added and filled from the data that is already there; the column it replaces is never
 * dropped. Nothing breaks and nothing is slow — the table simply carries both forever, one of them
 * silently stale, and the next reader cannot tell which is authoritative. That is the debt this
 * rule accounts for.
 *
 * ## The BACKFILL is the signal, and that is the whole design
 *
 * "The replaced column" is not a fact in the SQL. This package says so about itself elsewhere:
 * `ExpandContractTemplate` states that a new column's name and type are *"DECISIONS, not facts a
 * linter can read"*. Two readings that suggest themselves both fail on that:
 *
 * - **`ADD COLUMN` with no later `DROP COLUMN`** fires on every ordinary column addition — the most
 *   common migration there is. A false-positive machine, switched off inside a week, taking the
 *   real findings with it.
 * - **Name similarity** (`email` → `email_new`, `_v2`) guesses an intention out of a string. It
 *   breaks on the first project with another convention and cannot be justified to the person it
 *   reports at.
 *
 * What IS in the SQL is the data move. An expand/contract writes the old value into the new column:
 *
 * ```sql
 * ALTER TABLE orders ADD COLUMN total_cents bigint;   -- expand
 * UPDATE orders SET total_cents = total * 100;        -- the backfill — THIS is the evidence
 * ALTER TABLE orders DROP COLUMN total;               -- contract
 * ```
 *
 * A column added for genuinely new data is not back-filled from the rows that already exist. So the
 * rule asks for the pair — added AND written to in this run — and reports only when nothing in the
 * run drops a column from that table.
 *
 * ## What it deliberately does NOT try to read
 *
 * The SOURCE column. In `SET total_cents = total * 100` it sits inside an expression, and lifting it
 * out means parsing expressions in a layer that exists to be free of grammar. It is also not needed:
 * the finding names the column that was ADDED and the table it sits on, which is enough to act on.
 * Naming the replaced one would mean guessing it.
 *
 * ## Why it reads the whole RUN
 *
 * The contract step belongs in a LATER migration — that separation IS the pattern. A rule reading
 * only its own file would report every correctly split pair, on a file whose author did nothing
 * wrong. So the question goes to the run-wide view, exactly as
 * {@see ConstraintValidationPendingRule} asks it, and for the same reason: that view exists to
 * WITHHOLD a finding the run as a whole disproves.
 *
 * On the single-file fast path the run is a slice, so a later `DROP COLUMN` is out of view and this
 * reports an end that is already closed. That is the fast path's standing direction of error — it
 * sees what it was given — and it is why the confidence is heuristic.
 */
final class ExpandWithoutContractRule extends AbstractPgsqlSafetyRule implements ProducesDebt, ProvidesRemediation
{
    /**
     * The word this debt is filed under, read from the neutral sequence rather than spelled here.
     *
     * Driver-NEUTRAL on purpose: the MySQL rule for the same shape files under the same word, so one
     * open end seen from two engines is ONE account rather than two that never reconcile. It
     * therefore lives on {@see ExpandContractTemplate}, which both engines already depend on — a
     * copy on this class would be a second spelling waiting to drift, and reaching for it from the
     * core template would be the core naming a driver.
     */
    public const string DEBT_KIND = ExpandContractTemplate::DEBT_KIND;

    public function debtKind(): string
    {
        return self::DEBT_KIND;
    }

    /**
     * The column this finding leaves behind, read from the finding's own object identity.
     *
     * Structural rather than parsed out of the message — the registrar's contract forbids reading a
     * sentence, because a sentence gets reworded and an identity must not move when it does.
     */
    public function debtReference(Finding $finding): ?string
    {
        return $finding->location->objectName;
    }

    /** The missing half, referenced from the expand/contract sequence rather than restated. */
    private readonly ExpandContractTemplate $template;

    public function __construct(string $projectRoot)
    {
        parent::__construct($projectRoot);

        $this->template = new ExpandContractTemplate;
    }

    public function id(): string
    {
        return 'PG.L4.EXPAND_WITHOUT_CONTRACT';
    }

    public function level(): Level
    {
        return Level::BackwardCompatibility;
    }

    /** Online: adding a column and writing to it blocks nothing. The debt is what is LEFT, not what it cost. */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** Heuristic: on the single-file fast path a later `DROP COLUMN` is out of view. */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
    }

    /** @return list<string> */
    public function limitations(): array
    {
        return [
            'a back-fill that runs in a queued job or a separate script instead of the migration is '
            .'not seen, so the pair reads as an ordinary column addition and nothing is reported — '
            .'the rule would rather stay silent than guess which additions were replacements',
            'the REPLACED column is never named: it sits inside the expression on the right of the '
            .'assignment, and reading it would mean parsing expressions in the layer that exists to '
            .'be free of grammar. The finding names the column that was added',
            'a contract step in a migration this run did not capture — the single-file fast path, or '
            .'a drop that happened in an earlier release — reads as missing, which is the same '
            .'direction of error the fast path carries everywhere',
        ];
    }

    /**
     * One statement, not four — because the expand and the back-fill already happened.
     *
     * This rule is the account of a deliberate sequence sitting mid-way, never a complaint about
     * it. Handing over the whole expand/contract recipe would tell somebody to add a column that is
     * already there, in a migration they are not allowed to edit.
     *
     * ⚠️ `{{old_column}}` reaches the reader UNFILLED, and that is deliberate. Which column the new
     * one replaced is a decision that does not appear in the statement — see this rule's own
     * limitations. A guessed name would read as decided; an empty placeholder reads as the question
     * it is.
     *
     * The names come from the verdict's own reading, so the payload can never point at a different
     * column than the finding names.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        $verdict = $this->verdict($statement);

        if (! $verdict instanceof RuleVerdict || $verdict->isUndetermined() || $verdict->isPass) {
            return null;
        }

        $context = [];

        $table = $statement->soleSubjectTarget(SchemaObjectType::Table) ?? $statement->soleTarget(SchemaObjectType::Table);

        if ($table instanceof StatementTarget) {
            $context['table'] = $table->qualifiedName();
        }

        return $this->template->forPendingContract($context, $this->id(), $this->downtimeClass());
    }

    #[Override]
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        if (! $statement->is(StatementKind::AddColumn)) {
            return null;
        }

        $column = $statement->soleTarget(SchemaObjectType::Column);
        $table = $statement->soleSubjectTarget(SchemaObjectType::Table) ?? $statement->soleTarget(SchemaObjectType::Table);

        // A debt this tool cannot name is one it must not record: an entry keyed on nothing collides
        // with every other one of its kind.
        if (! $column instanceof StatementTarget || ! $table instanceof StatementTarget) {
            return null;
        }

        $run = $statement->migration->runStatements;
        $tableName = $table->qualifiedName();

        // The expand is only an expand once something fills it. Without this the rule fires on every
        // ordinary `ADD COLUMN`, which is the reading this design exists to refuse.
        if (! $this->backfilledInThisRun($column->qualifiedName(), $tableName, $run)) {
            return null;
        }

        if ($this->contractedInThisRun($tableName, $run)) {
            return null;
        }

        $name = $this->qualifiedThroughTable($column, $table);

        return RuleVerdict::flag(
            sprintf(
                'The column `%s` is added to `%s` and filled from the data already in that table, and '
                .'nothing in this run drops the column it replaces. That first half is the right '
                .'move — writing both columns for a while is what lets old and new code run side by '
                .'side. The second half is what ends it: `ALTER TABLE %s DROP COLUMN <old>` once '
                .'every deployed reader has stopped using the old one. Until it runs, the table '
                .'carries two columns for one fact, one of them going stale, and nothing says which '
                .'is authoritative — silently, which is why this is the step that gets forgotten.',
                $name,
                $tableName,
                $tableName,
            ),
            objectName: $name,
            objectType: SchemaObjectType::Column,
        );
    }

    /**
     * Whether this run writes to the named column of the named table.
     *
     * The assignment targets come from the classifier, not from a text match on the canonical SQL:
     * the signature layer captures which columns a `SET` clause writes to, so this rule asks a
     * structural question. Reading grammar here is what that layer exists to prevent.
     *
     * @param  list<MigrationStatementDigest>  $runStatements
     */
    private function backfilledInThisRun(string $column, string $table, array $runStatements): bool
    {
        foreach ($runStatements as $digest) {
            if ($digest->kind !== StatementKind::Dml) {
                continue;
            }

            if (! in_array($column, $digest->keyColumns, true)) {
                continue;
            }

            if ($this->addressesTable($digest, $table)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether this run drops any column from the named table.
     *
     * ANY column, not the replaced one — which this rule never learns. A drop on the same table in
     * the same run is the contract step by construction: nothing else drops a column there while a
     * new one is being back-filled.
     *
     * @param  list<MigrationStatementDigest>  $runStatements
     */
    private function contractedInThisRun(string $table, array $runStatements): bool
    {
        return array_any($runStatements, fn (MigrationStatementDigest $digest): bool => $digest->kind === StatementKind::DropColumn && $this->addressesTable($digest, $table));
    }

    /** Whether a captured statement's table target is the one named. */
    private function addressesTable(MigrationStatementDigest $digest, string $table): bool
    {
        return array_any($digest->targets, fn (StatementTarget $target): bool => $target->type === SchemaObjectType::Table && $target->qualifiedName() === $table);
    }

    /**
     * The column's name, qualified through the schema of the TABLE that holds it.
     *
     * A column is named WITHIN its table: `ALTER TABLE public.orders ADD COLUMN total_cents …`
     * qualifies the table and never the column, so a rule reading only the column target gets a bare
     * name — while a catalog-side reader has the schema and would write `public.total_cents`. Two
     * spellings of one column are TWO debts, because an entry's identity hashes the object string,
     * and the account would double while the reconciliation never converged.
     *
     * **When the statement names no schema, neither does this.** `ALTER TABLE orders …` resolves
     * through `search_path`, which a static reader does not have, and guessing `public` would be
     * right most of the time and silently wrong for every project that uses a schema. A wrong
     * identity is worse than a bare one, because it looks decided.
     */
    private function qualifiedThroughTable(StatementTarget $column, StatementTarget $table): string
    {
        $name = $column->qualifiedName();

        if (str_contains($name, '.')) {
            return $name;
        }

        $schema = $table->identifier->schema?->canonical;

        return $schema === null || $schema === '' ? $name : $schema.'.'.$name;
    }
}
