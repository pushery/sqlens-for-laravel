<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L1;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\ProvidesRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\AbstractPgsqlSafetyRule;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Rules\RuleDriverNotes;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A `DROP SCHEMA` in a migration's `up()` is every loss {@see DropTableRule} warns about, at once.
 *
 * ## Why this rule exists at all
 *
 * It was measured, not supposed. Against all 127 shipped rules, `DROP TABLE invoices` produced two
 * findings and `DROP SCHEMA public CASCADE` produced NONE — the tool reported dropping one table and
 * said nothing about dropping the namespace that contains every table. The sibling rule sits at
 * level 1, the level that always runs, which made the silence the wrong way round for a package
 * whose second principle is primum non nocere.
 *
 * The cause was upstream of the rules: a schema statement classified as `ddl_other`, the catch-all
 * that exactly one rule reads and reads to mean something else. Nothing was suppressing this
 * finding; there was no statement kind for a rule to fire on.
 *
 * ## CASCADE is the difference between bad and unbounded
 *
 * Without it PostgreSQL refuses a non-empty schema, so the statement is a safety check that failed
 * loudly. With it the drop takes every table, view, sequence and routine in the namespace AND every
 * dependent object outside it — a foreign key or view in another schema goes too. The message
 * therefore names it when it is there, the way the table rule does.
 *
 * ## What it deliberately does not claim
 *
 * The table rule stays silent when the same migration created the table it drops, because a table
 * born and dropped in one migration never held data a deploy would miss. This rule has no such
 * exemption, and the reason is a decision rather than an omission: `CREATE SCHEMA` is not captured
 * as its own statement kind, so the migration context cannot answer the question. Adding the case
 * only to answer it would put a second unread kind into the classifier — the unreachable-branch
 * trap this rule's own capture work was written to avoid. It is stated as a
 * limitation instead, which is what the honesty axis is for.
 *
 * Detection is on the canonical form and the classified target, never Laravel's raw grammar.
 */
final class DropSchemaRule extends AbstractPgsqlSafetyRule implements ProvidesRemediation
{
    /** The considered `none` this rule hands back, built once. */
    private readonly NoSafeSequenceTemplate $template;

    public function __construct(string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        parent::__construct($projectRoot, $driverNotes);

        $this->template = new NoSafeSequenceTemplate;
    }

    public function id(): string
    {
        return 'PG.L1.DROP_SCHEMA';
    }

    /**
     * A considered `none`, and NOT the staged drop its table-shaped sibling points at.
     *
     * `DropTableRule` can offer a sequence because the object is the whole subject: stop reading
     * one table, then drop that one table. A schema is a container, so the sequence it needs is
     * decided by what is inside it — tables still holding data want the staged drop, tables that
     * moved want `SET SCHEMA`, and a view another team depends on wants a conversation. This rule
     * reads one statement and never the catalog, so ordering that list would be inventing it.
     *
     * `strategy: none` is a CONCLUSION rather than a blank: a rule looked, and there is nothing
     * standard to recommend. What the reason CAN say is how the last step is made safe, which is
     * the part that does not depend on the contents — `RESTRICT` is the default precisely because
     * it refuses while the retirement is unfinished, and `CASCADE` is the waiver of that check.
     */
    public function remediationFor(MigrationStatementView $statement): ?RemediationPayload
    {
        if (! $statement->is(StatementKind::DropSchema)) {
            return null;
        }

        return $this->template->payload(
            'sqlens::messages.remediation.no_safe_sequence.drop_schema',
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
     * Online, for the same reason the table rule is: the drop takes a brief exclusive lock rather
     * than blocking on a scan or a rewrite. Its danger is the irreversible loss, which is the LEVEL
     * — the two axes stay separate.
     */
    public function downtimeClass(): DowntimeClass
    {
        return DowntimeClass::Online;
    }

    /** @return list<string> */
    public function limitations(): array
    {
        return [
            'a schema this same migration created is reported like any other: CREATE SCHEMA is not '
            .'captured as its own statement kind, so the migration context cannot tell a scratch '
            .'namespace from a live one',
            'what the schema CONTAINED is not read — this is a statement-level rule, so the finding '
            .'names the reach of the statement rather than the rows actually lost',
        ];
    }

    protected function judge(MigrationStatementView $statement): ?string
    {
        if (! $statement->is(StatementKind::DropSchema)) {
            return null;
        }

        $schema = $statement->soleTarget(SchemaObjectType::Schema);
        $named = $schema instanceof StatementTarget ? ' '.$schema->qualifiedName() : '';

        return 'DROP SCHEMA'.$named.' in up() is irreversible loss once the deploy is past, and it is '
            .'not scoped to one object: a schema is the namespace every table in it lives in.'
            .$this->reachClause($statement->canonical)
            .' If the drop is intended, annotate the migration with #[SqlensAllowDestructive] and a reason.';
    }

    /**
     * The sentence that says how far the statement reaches — its own method, not a ternary.
     *
     * Both branches are real advice rather than one branch and an empty string, so both are worth
     * reading and both are worth covering. As a multi-line ternary inside `judge()` the coverage
     * driver attributed only the first line of each arm and reported the continuations as
     * unreached, which on a 100% floor is a red build over code that demonstrably ran.
     */
    private function reachClause(string $canonical): string
    {
        if (preg_match('/\bCASCADE\b/i', $canonical) === 1) {
            return ' It uses CASCADE, so every table, view, sequence and routine in the schema goes with it — and so does every object OUTSIDE the schema that depends on one of them.';
        }

        return ' Without CASCADE PostgreSQL refuses a schema that still contains anything, so this succeeds only on an already-empty namespace.';
    }
}
