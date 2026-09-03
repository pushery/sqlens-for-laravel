<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Lifecycle;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;

/**
 * An `UPDATE` or `DELETE` with no `WHERE` clause changes or removes EVERY row in the
 * table. In a migration that is almost never what was meant — a forgotten predicate
 * turns a targeted fix into a whole-table sweep, and a `DELETE` sweep is data loss with
 * no way back once the deploy is past. This is a lifecycle rule, not a PostgreSQL one:
 * the danger is identical on every engine, because it is a property of the statement,
 * not of how a particular server runs it.
 *
 * The flag is deterministic in the direction that matters: a statement with no `WHERE`
 * at all sweeps the whole table, with certainty. An `INSERT` is never flagged — it has
 * no `WHERE` by nature — and a statement that carries a `WHERE` (even a filtering one in
 * a sub-select) shows the intent to scope and is left alone; the rule targets the
 * forgotten predicate, not the deliberate bulk change.
 *
 * A deliberate whole-table data migration is declared with a `#[SqlensAllowDestructive]`
 * opt-in and a reason — the same signal that clears the level-1 destructive DDL rules,
 * because a knowing whole-table write is the same kind of reviewed decision. That opt-in
 * no longer silences the rule: the finding is produced and the opt-in becomes a named,
 * visible suppression at the reporting layer, its reason shown, so the sweep is never
 * hidden. Detection is on the canonical form and the classified kind, never on Laravel's
 * raw grammar.
 */
final class DmlWithoutWhereRule extends AbstractLifecycleRule implements ProvidesRemediation
{
    /** The considered `none` — this rule has looked, and the missing predicate is not ours to write. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    public function id(): string
    {
        return 'GEN.L1.DML_WITHOUT_WHERE';
    }

    /**
     * A considered `none`, and the clearest case in the package for why that value exists.
     *
     * The fix for a missing `WHERE` is the `WHERE` that was meant — and it is in somebody's head,
     * not in the statement. A template could only emit `WHERE {{predicate}}`, which is the linter
     * restating the problem as a form to fill in; anything more specific would be a GUESS at a
     * predicate, and a guessed predicate on a `DELETE` deletes the wrong rows. The one shape of
     * harm this package exists to prevent is not one it may risk producing itself.
     *
     * So the reason is the payload. It names the two ways out — write the predicate, or declare the
     * whole-table write with `#[SqlensAllowDestructive]` and a reason — and the verification line
     * says what that opt-in does and does not do: it records the review, it does not silence the
     * finding.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if ($this->judge($statement) === null) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.dml_without_where',
            'sqlens::messages.remediation.no_safe_sequence.verification',
            $this->id(),
            $this->downtimeClass(),
        );
    }

    public function level(): Level
    {
        return Level::Destructive;
    }

    /**
     * Online: a whole-table `UPDATE`/`DELETE` takes row locks and writes a lot of WAL,
     * but it does not take the table-wide ACCESS EXCLUSIVE lock a blocking DDL does —
     * reads and writes to other rows proceed. The danger is the unintended data change,
     * which is the LEVEL, kept apart from the deploy-time lock impact this axis models.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::Dml)) {
            return null;
        }

        // Only UPDATE and DELETE sweep existing rows; an INSERT has no WHERE by nature
        // and is not the mistake this rule looks for.
        if (preg_match('/^(?:UPDATE|DELETE)\b/', $statement->canonical) !== 1) {
            return null;
        }

        // A WHERE anywhere in the statement — even a filtering sub-select — shows the
        // intent to scope. The rule fires on the total absence of one, and on the one
        // shape that is a WHERE only typographically (see below).
        $alwaysTrue = false;

        if (preg_match('/\bWHERE\b(.*)$/s', $statement->canonical, $where) === 1) {
            if (! $this->scopesNothing($where[1])) {
                return null;
            }

            $alwaysTrue = true;
        }

        $verb = str_starts_with($statement->canonical, 'DELETE') ? 'DELETE' : 'UPDATE';

        if ($alwaysTrue) {
            return $verb.' with a WHERE clause that is always true touches every row in the table, '
                .'exactly as a missing one would — '
                .($verb === 'DELETE' ? 'data loss with no way back once the deploy is past. ' : 'a full-table rewrite rather than the subset the predicate looks like it scopes. ')
                .'Replace the placeholder predicate with the one you meant, or — if a whole-table '
                .strtolower($verb).' is intended — annotate the migration with #[SqlensAllowDestructive] and a reason.';
        }

        return $verb.' without a WHERE clause '
            .($verb === 'DELETE' ? 'removes every row in the table — data loss with no way back once the deploy is past. ' : 'rewrites every row in the table, not the subset a forgotten predicate was meant to scope. ')
            .'Add the WHERE clause you meant, or — if a whole-table '.strtolower($verb).' is intended — annotate the '
            .'migration with #[SqlensAllowDestructive] and a reason.';
    }

    /**
     * Whether a WHERE predicate excludes no row at all — `WHERE 1=1`, `WHERE TRUE`.
     *
     * Such a clause is a WHERE only typographically. It is what a query generator emits as
     * a placeholder to append real conditions to, and a migration that ships with the
     * placeholder alone sweeps the whole table while LOOKING scoped — the more dangerous
     * shape of the two, because a reviewer's eye stops at the keyword.
     *
     * Deliberately narrow: the WHOLE predicate must be the constant. `WHERE 1=1 AND
     * tenant_id = 5` really is scoped, and flagging it would be the cry-wolf that gets a
     * linter switched off. Anything more ambitious would mean evaluating SQL expressions,
     * which is a database's job and not a static reader's.
     */
    private function scopesNothing(string $predicate): bool
    {
        $predicate = trim(rtrim(trim($predicate), ';'));

        // One layer of parentheses is idiomatic enough to be worth folding; deeper nesting
        // is not a shape anybody writes by hand for a constant.
        if (preg_match('/^\((.*)\)$/s', $predicate, $inner) === 1) {
            $predicate = trim($inner[1]);
        }

        return preg_match('/^(?:TRUE|1\s*=\s*1)$/i', $predicate) === 1;
    }
}
