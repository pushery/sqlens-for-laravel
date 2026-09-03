<?php

declare(strict_types=1);

namespace Pushery\SQLens\Audit;

use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\Rule;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * What came out of asking every rule about every subject: the findings, AND which rules were asked.
 *
 * The second half is the point. A dispatch that returned findings alone cannot answer the question
 * a reader actually has about a quiet report — did this rule look and find nothing, or was it never
 * given anything to look at? Both produce no finding, and on a run whose reader came back short the
 * second is the ordinary case rather than the exotic one.
 *
 * Counting does not answer it either. The active-rule count is fixed before anything is read, so it
 * reads identically over a full catalog and an empty one. Only the identities collected here
 * separate "asked and silent" from "never asked", which is why they travel as a set rather than as
 * a number.
 *
 * ## Why `appliesTo()` is NOT the seam this reads
 *
 * It is the obvious one and it carries none of the answer. `AbstractCatalogRule::appliesTo()` is
 * `final` and true for every schema object, deliberately — so recording there would mark every
 * catalog rule as evaluated the moment any object was read, including a rule about `pg_hba` lines on
 * a run that read none. That is not a useless field but a harmful one: it would state that a check
 * ran, in the public report, about a check that never saw its subject.
 *
 * The narrowing that matters lives one layer in, inside each rule's `judgeSchemaObject()`, where it
 * is invisible from here and shaped exactly like "my subject, and it is fine". So the rules that
 * narrow SAY so, through {@see DeclaresJudgedObjectTypes}, and this reads that. A rule without the
 * interface judges whatever it is handed, so any subject evaluates it — and a guard keeps that
 * default from becoming a lie.
 *
 * ## Why a rule with no subject is absent rather than recorded as skipped
 *
 * There is no moment at which such a rule is met: the loop walks SUBJECTS. Its absence from this set
 * IS the record, and the comparison that consumes it — one reading against another — is where
 * absence becomes a statement. Inverting it (recording the skipped ones) would need the loop to
 * enumerate the rules a second time, and the second enumeration is where the two would drift on what
 * counts as a rule.
 */
final readonly class RuleEvaluation
{
    /**
     * @param  list<Finding>  $findings
     * @param  list<string>  $evaluatedRuleIds  every rule that judged at least one subject, once each
     */
    private function __construct(
        public array $findings,
        public array $evaluatedRuleIds,
    ) {}

    /**
     * Ask every rule about every subject it applies to.
     *
     * @param  list<Rule>  $rules
     * @param  list<SchemaObject>  $subjects
     */
    public static function of(array $rules, array $subjects): self
    {
        $findings = [];
        $evaluated = [];

        foreach ($subjects as $object) {
            // appliesTo() decides and evaluate() judges — the contract's own division, honored
            // here rather than left to each rule's internal re-check. Expressed as a filter instead
            // of a `continue` because every shipped catalog rule accepts every schema object today,
            // so a skip branch would be a statement nothing executes.
            foreach (array_filter($rules, static fn (Rule $rule): bool => $rule->appliesTo($object)) as $rule) {
                // Recorded on the way IN, before the verdict, and only when this rule judges THIS
                // KIND of subject. Both halves are load-bearing. Recording only rules that produced
                // a finding would collapse "judged and found nothing" back into "never ran", which
                // is the distinction the set exists for; recording every rule the dispatcher offered
                // the object to would mark a rule as evaluated by a subject it discards unread.
                if (self::judges($rule, $object)) {
                    $evaluated[$rule->id()] = true;
                }

                foreach ($rule->evaluate($object) as $finding) {
                    $findings[] = $finding;
                }
            }
        }

        return new self($findings, array_keys($evaluated));
    }

    /**
     * Whether this subject is one this rule actually judges.
     *
     * A rule that declares nothing judges whatever it is handed — true for every table rule, and the
     * only reading of silence that is not a guess. `tests/Unit/Rules/JudgedObjectTypeDeclarationTest.php`
     * is what keeps it true: a rule whose body narrows by type and does not declare fails there,
     * because otherwise the default would quietly start meaning "we did not check".
     */
    private static function judges(Rule $rule, SchemaObject $object): bool
    {
        return ! $rule instanceof DeclaresJudgedObjectTypes
            || in_array($object->type, $rule->judgedObjectTypes(), true);
    }
}
