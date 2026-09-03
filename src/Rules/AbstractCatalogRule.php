<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\JudgesMigrationStatements;
use Pushery\SQLens\Contracts\JudgesSchemaObjects;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Contracts\Subject;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationSql;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A rule whose PRIMARY subject is a live SCHEMA OBJECT rather than a migration statement.
 *
 * {@see AbstractSafetyRule} deliberately cannot serve one: its `appliesTo()` and `evaluate()` are
 * `final` and take `MigrationSql` alone, so every lint rule goes through exactly one path. That
 * `final` is worth keeping — it is what makes the lint family's dispatch impossible to get wrong —
 * which means a rule with a different subject needs its own base rather than a loosened one.
 *
 * ## It was a dual-subject base first, it lost that half, and it is back — with a user
 *
 * The first version dispatched on BOTH subjects: a rule would answer from a migration and from a
 * catalog, from one implementation, with the migration answer allowed to be `undetermined`. The
 * reasoning was that splitting a rule in two lets the halves drift on the one thing that must not —
 * what counts as a violation.
 *
 * Then the first rule built on it turned out to have nothing to say about a migration at all (see
 * {@see ForeignKeyWithoutIndexRule} for why), and the
 * migration half became machinery no rule used. Keeping it would have meant an `appliesTo()` that
 * accepts a subject nothing does anything with, and a hook every catalog rule implements by
 * returning null — reachable only from a test written to reach it, which is the shape of a guard
 * that guards nothing. So it was removed, with the note that a genuinely dual rule brings it back
 * WITH its first user.
 *
 * That user arrived: `PG.L5.FK_NO_INDEX` cannot prove the ABSENCE of an index from migration text
 * in general, but it CAN when the migration creates the table itself and therefore carries that
 * table's whole index history. The half is back as an OPT-IN — a rule declares it by implementing
 * {@see JudgesMigrationStatements}, exactly as the mirror-image {@see JudgesSchemaObjects} lets a
 * lint rule declare a catalog half — so the twenty rules that can only read a catalog carry no
 * hook, and the machinery that exists is machinery something uses.
 */
abstract class AbstractCatalogRule implements JudgesSchemaObjects, Rule
{
    use RuleMetadataDefaults;

    /**
     * The engine-note register, read once per rule instance and only when a migration verdict
     * actually has to be built.
     *
     * Lazy rather than a constructor parameter for a measured reason: every catalog rule is
     * constructed on every run, the register is a file read, and almost no catalog rule has a
     * migration half at all — paying for the file on construction would charge the whole family
     * for one rule's opt-in. The same shape {@see Settings\AbstractServerSettingRule} uses for its
     * matrix.
     */
    private ?RuleDriverNotes $driverNotes = null;

    /**
     * A catalog rule judges a SCHEMA, and a schema is the same object on every node that carries the
     * database. Withholding these on a replica would make a replica-targeted audit report nothing at
     * all about the one thing it can see perfectly well.
     */
    public function instanceScope(): InstanceScope
    {
        return InstanceScope::Database;
    }

    /**
     * The repo root. A catalog finding's location is an instance and an object name, not a file —
     * but the rule registries construct every rule the same way, and a base that refused the
     * argument would make this family the one exception a registration has to remember.
     */
    public function __construct(protected string $projectRoot) {}

    abstract public function id(): string;

    abstract public function level(): Level;

    abstract public function category(): Category;

    /**
     * The verdict against a live schema object — a fail, an undetermined, or nothing.
     *
     * @return list<RuleVerdict>
     */
    abstract public function judgeSchemaObject(SchemaObject $object): array;

    /**
     * A live schema object always; a migration statement only for a rule that says it judges one.
     *
     * The `final` stays for the same reason it does on {@see AbstractSafetyRule}: what a family
     * dispatches on must not be overridable per rule, or the one thing every rule in the family
     * shares stops being shared. What a rule MAY do is declare the second subject by implementing
     * {@see JudgesMigrationStatements}.
     */
    final public function appliesTo(Subject $subject): bool
    {
        return $subject instanceof SchemaObject
            || ($subject instanceof MigrationSql && $this instanceof JudgesMigrationStatements);
    }

    /** @return list<Finding> */
    final public function evaluate(Subject $subject): array
    {
        if ($subject instanceof MigrationSql && $this instanceof JudgesMigrationStatements) {
            // Built by the shared factory, so a migration finding from this base and one from the
            // lint base are the same object shape — see MigrationVerdicts for why that is not
            // left to each base to get right on its own.
            return MigrationVerdicts::toFindings(
                $this->judgeStatement($subject->canonicalView()),
                $this,
                $subject,
                $this->projectRoot,
                $this->driverNotes ??= RuleDriverNotes::bundled(),
            );
        }

        if (! $subject instanceof SchemaObject) {
            return [];
        }

        return CatalogVerdicts::toFindings($this->judgeSchemaObject($subject), $this, $subject);
    }

    /**
     * The suites this rule appears in — declared per rule, never defaulted here.
     *
     * The first draft defaulted to both, on the reasoning that a rule reaching this base runs in
     * both. That is a claim about the base's REACH, and a rule's suite list has to be a claim about
     * its own behavior: a rule that can only answer from a catalog says `audit`, whatever base it
     * extends. The registry export is what a reader trusts to say where a finding can come from, so
     * an inherited default that happened not to match would be an advertisement nothing checks.
     *
     * @return list<Suite>
     */
    abstract public function suites(): array;

    /**
     * The message prefix, identical across both subjects.
     *
     * One rule, one prefix — a reader comparing a lint report and an audit report has to be able to
     * see that the same rule spoke. It reads `sqlens.lint` today because that is what every rule in
     * the package reports under and the string is part of the published output; renaming it fleet-
     * wide is a change to what consumers parse, not a detail to slip into a rule.
     */
    final public function messagePrefix(): string
    {
        return 'sqlens.lint';
    }
}
