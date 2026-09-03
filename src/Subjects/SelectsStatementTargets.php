<?php

declare(strict_types=1);

namespace Pushery\SQLens\Subjects;

use Pushery\SQLens\Canonical\StatementTarget;
use Pushery\SQLens\Canonical\TargetRole;

/**
 * Selecting one target out of a statement's list — the ONE implementation both carriers share.
 *
 * ## Why this is a trait rather than two copies
 *
 * {@see MigrationStatementView} and {@see MigrationStatementDigest} carry the same `targets` list for
 * two audiences: the statement a rule is judging, and a neighbor it reads out of the stream. Both
 * had their own `soleTarget()`, byte-identical, with a docblock on one saying it follows "the same
 * rule" as the other — a promise kept by hand.
 *
 * That was survivable while the rule was three lines. It stopped being survivable when a SECOND
 * question arrived: with `soleSubjectTarget()` on only one of them, a reader holding a digest could
 * not ask it, and the obvious repair was a fourth copy. Four methods for two questions, with the
 * role logic written twice, is the shape this repository has already paid for elsewhere — one rule,
 * two implementations, both green, free to disagree.
 *
 * `tests/Unit/Subjects/StatementTargetSelectionTest.php` holds the two carriers to the same answers,
 * so "there is only one implementation" is a check rather than a sentence.
 */
trait SelectsStatementTargets
{
    /**
     * The single target of the given object type, or null when there is not exactly one.
     *
     * "Exactly one" rather than "the first" on purpose: a statement that names two tables is not one
     * a table-scoped reader should quietly pick a side on. A `FOREIGN KEY … REFERENCES` names two,
     * and which of them sorts first depends on the schema — so "the first" is right for the example
     * everybody tests with and silently wrong for the next project's names.
     */
    public function soleTarget(SchemaObjectType $type): ?StatementTarget
    {
        return $this->onlyOne(
            static fn (StatementTarget $target): bool => $target->type === $type,
        );
    }

    /**
     * The single target of the given type that the statement ACTS ON, or null when there is not
     * exactly one.
     *
     * The difference from {@see self::soleTarget()} is one statement shape: a foreign key names two
     * tables and only one of them is being altered. `soleTarget()` answers null there — correctly,
     * because it cannot tell them apart and picking a side silently is the failure it exists to
     * avoid. This one can, because the grammar declared it (see {@see TargetRole}).
     *
     * Kept SEPARATE rather than folded into `soleTarget()`: thirty-odd readers call that method
     * today and every one of them is silent on foreign-key statements. Teaching it to answer would
     * hand all of them a table they have never seen and change what they report — a decision for
     * each of those readers, not a side effect of this one.
     */
    public function soleSubjectTarget(SchemaObjectType $type): ?StatementTarget
    {
        return $this->onlyOne(
            static fn (StatementTarget $target): bool => $target->type === $type && $target->isSubject(),
        );
    }

    /**
     * The one target matching the predicate, or null when there is not exactly one.
     *
     * @param  callable(StatementTarget): bool  $matches
     */
    private function onlyOne(callable $matches): ?StatementTarget
    {
        $matching = array_values(array_filter($this->targets, $matches));

        return count($matching) === 1 ? $matching[0] : null;
    }
}
