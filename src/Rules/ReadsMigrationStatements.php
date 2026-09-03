<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Contracts\JudgesSchemaObjects;
use Pushery\SQLens\Contracts\Subject;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Subjects\MigrationSql;
use Pushery\SQLens\Subjects\MigrationStatementView;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * Everything a rule needs to be asked about a MIGRATION — except what it means.
 *
 * ## Why this is a trait and not the base class it was
 *
 * All of this lived in {@see AbstractSafetyRule}, whose own docblock states the reason it cannot
 * stay there: *"Every rule in this family is a safety rule; that is what the family means."* The
 * category is `final` on that class, deliberately — the family IS the meaning.
 *
 * A security rule over a migration needs the same machinery and a different meaning. Extending the
 * safety base would either silently file it under `Safety` or require un-finalizing the one line
 * that keeps sixty-five safety rules honest. Under PHP's single inheritance there is no third
 * class to descend from, because the subject family and the category family are different axes.
 *
 * So the machinery moves to where both can have it, and each base keeps its own `final category()`.
 * The pattern is the one this package already uses for cross-cutting capability — the difference is
 * only that a contract cannot carry an implementation and this must.
 *
 * ## What did NOT change
 *
 * Every method here is byte-identical to the one it replaced, including the `final` markers: what a
 * lint rule dispatches on must not be overridable per rule. The extraction is mechanical, and the
 * existing suite over sixty-five safety rules is what proves it.
 */
trait ReadsMigrationStatements
{
    // The answers every rule family gives the same way. Held once, so a second family cannot end up
    // disagreeing with this one about what "the default" is.
    use RuleMetadataDefaults;

    /**
     * Where a rule's page lives. Kept as an alias of {@see RuleDocumentationUrl::BASE} so the
     * host is one string across BOTH rule families — the safety rules and the capture rules,
     * which are not safety rules and once carried the address as a literal.
     */
    public const string DOCUMENTATION_BASE = RuleDocumentationUrl::BASE;

    private readonly RuleDriverNotes $driverNotes;

    /** The rule id, `<AREA>.L<level>.<SLUG>`. Public API from 1.0: named once, never renamed. */
    abstract public function id(): string;

    abstract public function level(): Level;

    /**
     * A lint rule reasons about migration FILES and never addresses an instance, so this is not
     * consulted on any run it takes part in today. It is declared anyway, and declared as the
     * conservative value rather than a convenient one: the day a rule of this family is admitted to
     * the audit suite, the wrong default would let it answer on a machine that cannot support the
     * question — silently, because nothing about the change would mention scope.
     */
    public function instanceScope(): InstanceScope
    {
        return InstanceScope::Instance;
    }

    public function __construct(protected string $projectRoot, ?RuleDriverNotes $driverNotes = null)
    {
        $this->driverNotes = $driverNotes ?? RuleDriverNotes::bundled();
    }

    final public function messagePrefix(): string
    {
        return 'sqlens.lint';
    }

    /**
     * The slug of a rule id: lowercased, with BOTH separators — the dots between
     * segments and the underscores inside one — folded to dashes.
     *
     * The underscore is the part that is easy to get wrong, and it was: a slug that
     * keeps it produces `pg-l2-index_not_concurrent`, which reads plausibly and matches
     * nothing. Every rule shipped before this class derives `cap-l0-not-capturable`
     * from `CAP.L0.NOT_CAPTURABLE`, so a second, underscore-keeping derivation would
     * have split one convention into two — and the only visible symptom would have been
     * a user following a link that 404s.
     */
    final public static function slug(string $ruleId): string
    {
        return RuleDocumentationUrl::slug($ruleId);
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Lint];
    }

    /**
     * The failing verdict for one statement as a message, or null when the rule has
     * nothing to flag. This is the common case — a rule that only ever flags or stays
     * silent implements this and nothing else.
     *
     * The rule sees the {@see MigrationStatementView} — the canonical facts and nothing
     * else: the normalized statement string, its classified kind and targets, and what
     * the surrounding migration does. There is no accessor for the raw grammar output or
     * the provenance, which is the grammar-drift defense restated at the point it bites.
     *
     * It is not abstract, so a three-valued rule can override {@see verdict()} instead
     * and leave this at its silent default rather than carrying a method it never uses.
     */
    protected function judge(MigrationStatementView $statement): ?string
    {
        return null;
    }

    /**
     * The three-valued verdict: a flag, an undetermined, or nothing. The default wraps
     * {@see judge()}, so the common rules need only implement that. A rule with a real
     * third answer — a classifier that meets a case its data does not cover — overrides
     * this and returns {@see RuleVerdict::undetermined()} rather than a silent pass.
     */
    protected function verdict(MigrationStatementView $statement): ?RuleVerdict
    {
        $message = $this->judge($statement);

        return $message === null ? null : RuleVerdict::flag($message);
    }

    /**
     * A migration statement always; a live schema object only for a rule that says it judges one.
     *
     * The `final` stays: what a lint rule dispatches on must not be overridable per rule, or the
     * one thing every rule in the family shares stops being shared. What a rule MAY do is declare
     * a second subject by implementing {@see JudgesSchemaObjects} — an opt-in the twenty rules that
     * have nothing to say about a live table never see.
     */
    final public function appliesTo(Subject $subject): bool
    {
        return $subject instanceof MigrationSql
            || ($subject instanceof SchemaObject && $this instanceof JudgesSchemaObjects);
    }

    /** @return list<Finding> */
    final public function evaluate(Subject $subject): array
    {
        if ($subject instanceof SchemaObject && $this instanceof JudgesSchemaObjects) {
            // Built by the shared factory, so a rule that reaches a catalog from this base and one
            // that reaches it from AbstractCatalogRule cannot produce differently-shaped findings.
            return CatalogVerdicts::toFindings($this->judgeSchemaObject($subject), $this, $subject);
        }

        if (! $subject instanceof MigrationSql) {
            return [];
        }

        // Built by the shared factory, so a lint rule of this family and a catalog rule that
        // reaches a migration through JudgesMigrationStatements cannot produce differently-shaped
        // findings. The downtime class and confidence are stamped by the collector rather than
        // here, so both a fail and an undetermined carry them uniformly.
        return MigrationVerdicts::toFindings(
            $this->verdict($subject->canonicalView()),
            $this,
            $subject,
            $this->projectRoot,
            $this->driverNotes,
        );
    }
}
