<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A rule that judges only SOME kinds of schema object, saying which — so a run can tell whether it
 * was ever handed one.
 *
 * ## Why this cannot be read off `appliesTo()`
 *
 * It is the obvious place and it carries none of the answer. `AbstractCatalogRule::appliesTo()` is
 * `final` and returns true for every {@see SchemaObject}, on purpose: what a
 * family dispatches on must not be overridable per rule. So as far as the dispatcher can see, every
 * catalog rule applies to every object, and a rule about `pg_hba` lines looks exactly as evaluated
 * on a run that read none as on one that read forty.
 *
 * The narrowing happens one layer in, as a line like `if ($object->type !== SchemaObjectType::Grant)
 * { return []; }` inside `judgeSchemaObject()` — invisible from outside, and expressed as the same
 * empty answer a rule gives when its subject is fine. This interface is that line, moved somewhere a
 * caller can read it.
 *
 * ## Why opt-in rather than a method on the rule contract
 *
 * Adding a method to {@see Rule} or {@see JudgesSchemaObjects} breaks every implementer at once, for
 * a fact most rules do not have: a rule that genuinely judges any table has nothing to declare, and
 * forcing it to say "all of them" is a sentence that can only be wrong. Absence therefore means
 * exactly one thing — this rule judges whatever it is handed — and that meaning is held by a guard
 * rather than by hope: a rule whose source narrows by type and does not implement this fails
 * `tests/Unit/Rules/JudgedObjectTypeDeclarationTest.php`.
 */
interface DeclaresJudgedObjectTypes
{
    /**
     * The kinds of subject this rule judges. Never empty — a rule that judges nothing is not a rule.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array;
}
