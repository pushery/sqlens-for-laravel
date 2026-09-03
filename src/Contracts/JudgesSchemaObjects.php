<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\AbstractSafetyRule;
use Pushery\SQLens\Rules\CatalogVerdicts;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A rule that can also answer from a live schema object — the opt-in half of "one rule, two
 * subjects".
 *
 * ## Why an interface and not a base class
 *
 * {@see AbstractSafetyRule} has `appliesTo()` and `evaluate()` `final`, and
 * that is worth keeping: it is what makes the dispatch of every lint rule impossible to get wrong.
 * A rule that ALSO reads a catalog therefore cannot simply override them. Nor should the base grow
 * a catalog branch every lint rule must implement and almost none would use — machinery reachable
 * only from a test written to reach it is the shape of a guard that guards nothing.
 *
 * So the base checks for this interface, and a rule that has something to say about a live table
 * says so by implementing it. The lint path is untouched for the twenty rules that do not.
 *
 * ## When a rule should implement this
 *
 * When the QUESTION is the same and only the evidence differs. "Does this table have a usable
 * key?" is one question; a migration answers it about a table being born and a catalog answers it
 * about every table that exists, and the second can settle cases the first cannot. Splitting that
 * into two rules would be the same rule twice, free to drift on the one thing that must not: what
 * counts as a violation. Two DIFFERENT questions that happen to touch the same object are two
 * rules, and giving them one id would make an ignore-list entry mean two things.
 *
 * The finding is built by {@see CatalogVerdicts} either way, so a rule
 * reaching a catalog through this interface and one reaching it through
 * {@see AbstractCatalogRule} produce the same shape.
 */
interface JudgesSchemaObjects
{
    /**
     * The verdicts about this schema object — a fail, an undetermined, several, or none.
     *
     * A list rather than a single verdict because one table can carry several findings of the same
     * rule (one per foreign key, say), and returning the first would silently hide the rest.
     *
     * @return list<RuleVerdict>
     */
    public function judgeSchemaObject(SchemaObject $object): array;
}
