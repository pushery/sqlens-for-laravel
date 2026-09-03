<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Contracts\JudgesMigrationStatements;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Deploy\Contracts\DeclaresOperationClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\MigrationSql;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Turns a rule's verdict about ONE migration statement into a finding — once, for every base that
 * has migration subjects.
 *
 * The exact counterpart of {@see CatalogVerdicts}, and it exists for the same reason. Two bases
 * reach a migration statement now: {@see AbstractSafetyRule}, whose whole family judges them, and
 * {@see AbstractCatalogRule}, for a catalog rule that ALSO has something to say about one
 * ({@see JudgesMigrationStatements}). Letting each build its own finding would be the second code
 * path this package keeps refusing: the two would drift on the location shape, on whether the
 * engine note is applied, or on how an undetermined verdict is carried — and the drift would be
 * invisible, because each half looks correct on its own.
 *
 * It takes the whole {@see Rule} rather than a dozen arguments, so a metadata field added to that
 * contract later cannot be forgotten here.
 *
 * What it deliberately does NOT do is stamp the confidence or the downtime class. Those come from
 * the collector, which is where a rule that DERIVES its class per statement is asked — putting a
 * second stamping here would give one finding two answers.
 */
final readonly class MigrationVerdicts
{
    /**
     * @param  RuleVerdict|null  $verdict  null when the rule had nothing to say — the common case
     * @param  string  $projectRoot  so the location is repo-relative rather than absolute: an
     *                               absolute path in a report destroys diffability and leaks the
     *                               developer's directory layout into a shared artifact
     * @return list<Finding>
     */
    public static function toFindings(
        ?RuleVerdict $verdict,
        Rule $rule,
        MigrationSql $subject,
        string $projectRoot,
        RuleDriverNotes $driverNotes,
    ): array {
        if (! $verdict instanceof RuleVerdict) {
            return [];
        }

        $object = self::objectOf($verdict, $rule, $subject);

        $location = Location::inMigration(
            file: $subject->sourceFile,
            migrationClass: $subject->migrationClass,
            statementIndex: $subject->statementIndex,
            direction: $subject->direction,
            projectRoot: $projectRoot,
            objectName: $object['name'],
            objectType: $object['type'],
        );

        // The engine note, appended here rather than inside the rule. A driver-neutral rule that
        // must say something engine-specific would otherwise have to know an engine by name — the
        // exact coupling the architecture guards forbid — so the sentence lives in a register and
        // the rule stays neutral. Absent for almost every rule, which is why it is a no-op by
        // default rather than something each rule opts into.
        $message = $driverNotes->apply($verdict->message, $rule->id(), $subject->context()->driver);

        $reason = $verdict->undeterminedReason;

        if ($reason instanceof UndeterminedReason) {
            return [Finding::undetermined(
                $rule->id(),
                $rule->messagePrefix(),
                $message,
                $reason,
                $location,
                $rule->category(),
                $rule->level(),
                $rule->stability(),
                $rule->documentationUrl(),
                $subject->context(),
                $verdict->severity ?? $rule->severity(),
            )];
        }

        return [Finding::fail(
            $rule->id(),
            $rule->messagePrefix(),
            $message,
            $location,
            $rule->category(),
            $rule->level(),
            $rule->stability(),
            $rule->documentationUrl(),
            $subject->context(),
            $verdict->severity ?? $rule->severity(),
        )];
    }

    /**
     * The object a finding is about, filled in for a rule that declares an operation class.
     *
     * ## Why this is here and not in each rule
     *
     * A rule implementing {@see DeclaresOperationClass} says its findings describe an operation
     * whose SIZE changes what they cost. That claim is worth nothing unless the finding also names
     * the object to size: {@see FindingEscalation} looks the statistics up by
     * `location->objectName` and drops any finding that carries none, before it reads anything.
     *
     * Measured the hard way. All six declaring rules left `RuleVerdict::flag()`'s optional
     * `objectName` at its default, so live escalation was dead for every operation class while
     * twelve unit arms passed — each of them supplying the object name from its own test double,
     * which is exactly where the missing value came from. Filling it per rule would have been six
     * edits and a seventh rule away from the same silence.
     *
     * So it is derived once, here, at the seam every migration finding already passes through: the
     * statement's sole SUBJECT table target. Sole rather than first, deliberately — a statement
     * touching two tables it merely names has no single object whose size decides anything, and
     * guessing one would weigh a finding against the wrong table quietly. A rule that knows better
     * still wins: an explicit `objectName` on the verdict is never overwritten.
     *
     * SUBJECT rather than merely sole, and that distinction is newer. A foreign key names two tables, so the
     * plain sole reading answered null and every foreign-key finding lost its object — the same
     * silent death of escalation described above, in the commonest two-table statement there is.
     * The role comes from the grammar, so this is not the guess the paragraph above rules out.
     *
     * @return array{name: string|null, type: SchemaObjectType|null}
     */
    private static function objectOf(RuleVerdict $verdict, Rule $rule, MigrationSql $subject): array
    {
        if ($verdict->objectName !== null || ! $rule instanceof DeclaresOperationClass) {
            return ['name' => $verdict->objectName, 'type' => $verdict->objectType];
        }

        // The SUBJECT table, not the sole one — and the difference is one statement shape. A
        // `FOREIGN KEY … REFERENCES` names two tables, so the sole reading answered null and the
        // finding carried no object at all; escalation drops such a finding before reading any
        // statistics, so size never spoke for a foreign key. Which of the two decides the cost is
        // not a guess: validating the constraint scans the ALTERED table's rows and probes an index
        // on the referenced side, and the grammar already declared which is which.
        $table = $subject->canonicalView()->soleSubjectTarget(SchemaObjectType::Table);

        return $table instanceof StatementTarget
            ? ['name' => $table->qualifiedName(), 'type' => SchemaObjectType::Table]
            : ['name' => null, 'type' => $verdict->objectType];
    }
}
