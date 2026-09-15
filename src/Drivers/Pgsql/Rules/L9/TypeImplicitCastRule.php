<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L9;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Remediation\RemediationStep;
use Pushery\SQLens\Remediation\RemediationStepKind;
use Pushery\SQLens\Remediation\RemediationStrategy;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Pedantic\ImplicitCast;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A foreign key whose two ends are not the same type.
 *
 * ## The reason is NOT the one everybody gives, and that was measured
 *
 * The usual argument is that a mismatched pair still compares but stops using the index. Against
 * PostgreSQL 18.4 that is false:
 *
 * ```
 * EXPLAIN SELECT * FROM k1 WHERE pid = 42::bigint;   -- pid is int, referencing a bigint
 *   ->  Index Scan using k1_pid_idx on k1
 *         Index Cond: (pid = '42'::bigint)
 * ```
 *
 * The btree integer operator family carries cross-type operators, so the index is used. A rule
 * built on the index argument would ship advice that is confident, specific and wrong.
 *
 * ## What is actually wrong is worse, and it is DATED
 *
 * An `int` column referencing a `bigint` key can only ever point at the first 2^31 of its target's
 * 2^63 values. Nothing about the schema says so. Every test passes, because a test database never
 * gets there. Then the parent sequence crosses 2,147,483,647 — years after the migration — and
 * every insert into the child fails with an out-of-range error naming a column nobody connects to a
 * foreign key.
 *
 * So this rule reports the NARROWING direction as the finding it is, and reports a widening or a
 * differing non-integer pair for what it is too: a conversion the schema did not intend.
 *
 * ## Audit only, and that is structural
 *
 * A migration adding a foreign key carries the type of NEITHER column — the types live in the
 * `CREATE TABLE` statements, and the referenced table is almost always created by a migration that
 * is no longer pending when this one runs. The catalog is the only place both ends exist at once.
 * A lint half would therefore answer `undetermined` for nearly every foreign key, which is noise
 * rather than honesty.
 */
final class TypeImplicitCastRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, ProvidesSchemaObjectRemediation
{
    /**
     * Pairs PostgreSQL stores identically, so comparing across them costs nothing.
     *
     * Measured rather than assumed — `pg_type` reports the same `typlen`, `typalign` and
     * `typstorage` for `text` and `varchar`. `bpchar` is deliberately NOT in the group: it pads to
     * its declared length, so comparing it against either of the others is a real conversion with a
     * real answer change.
     *
     * @var list<list<string>>
     */
    private const array EQUIVALENT = [
        ['text', 'varchar', 'character varying'],
    ];

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'PG.L9.TYPE_IMPLICIT_CAST';
    }

    public function level(): Level
    {
        return Level::Pedantic;
    }

    public function category(): Category
    {
        return Category::Idiom;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $offenders = [];
        $unread = [];

        foreach (ImplicitCast::pairs($object) as $pair) {
            if ($pair['localType'] === null || $pair['farType'] === null) {
                // One side unread. Not a pass: the question was asked and not answered, and the two
                // must not look alike — a schema whose catalog reading lost a column would
                // otherwise report every one of its foreign keys as fine.
                $unread[] = $pair['constraint'].' ('.$pair['local'].' → '.$pair['far'].')';

                continue;
            }

            if (ImplicitCast::sameType($pair['localType'], $pair['farType'], self::EQUIVALENT)) {
                continue;
            }

            $offenders[] = $this->sentence($pair);
        }

        if ($offenders !== []) {
            sort($offenders, SORT_STRING);

            return [RuleVerdict::flag(implode(' ', $offenders), $object->qualifiedName, $object->type)];
        }

        if ($unread !== []) {
            sort($unread, SORT_STRING);

            return [RuleVerdict::undetermined(
                'The type of at least one end of these foreign keys was not established, so whether the two sides '
                .'agree is unknown rather than fine: '.implode(', ', $unread).'.',
                UndeterminedReason::CatalogReadFailed,
            )];
        }

        return [];
    }

    /** @param  array{constraint: string, local: string, localType: ?string, far: string, farType: ?string}  $pair */
    private function sentence(array $pair): string
    {
        $local = ImplicitCast::integerWidth((string) $pair['localType']);
        $far = ImplicitCast::integerWidth((string) $pair['farType']);

        if ($local !== null && $far !== null && $local < $far) {
            return sprintf(
                '`%s` is `%s` and references `%s`, which is `%s`. The narrower side can only ever point at the '
                .'first %s of the wider one\'s values, so this key stops working the day the referenced sequence '
                .'passes that number — long after the migration that set it up. Widen `%s` to `%s`.',
                $pair['local'], $pair['localType'], $pair['far'], $pair['farType'],
                number_format((2 ** ($local * 8 - 1)) - 1),
                $pair['local'], $pair['farType'],
            );
        }

        return sprintf(
            '`%s` is `%s` and references `%s`, which is `%s`. PostgreSQL compares them by converting one side, '
            .'which the schema did not ask for and nothing records. Declare both ends as the same type.',
            $pair['local'], $pair['localType'], $pair['far'], $pair['farType'],
        );
    }

    /**
     * The fix material for the one direction of this finding that has a standard sequence.
     *
     * ## Only the narrowing integer pair, and only when it is alone on its constraint
     *
     * This rule reports three different shapes under one id, and exactly one of them has an answer
     * that does not depend on knowing the application: a single-column key whose referencing side
     * is a NARROWER integer than the key it points at. That one is dated -- it breaks when the
     * parent sequence crosses the child's ceiling -- and its end state is not a judgment call: the
     * child has to be as wide as what it references.
     *
     * The other two get a considered `none` rather than a null, because this rule looked at them
     * and reached a conclusion. A composite key cannot be widened one column at a time without
     * deciding an order, and the order depends on what reads the table while each exclusive lock is
     * held. A pair where the PARENT is the narrower side points the other way: matching them means
     * widening the referenced key, and narrowing the child to fit would cement the smaller ceiling.
     * A non-integer pair -- a timestamp against a datetime -- has an answer per pair that depends on
     * which side is telling the truth about the data.
     *
     * ## Why the sequence and not the one statement, and why the statement is in the precondition
     *
     * `ALTER TABLE … ALTER COLUMN … TYPE bigint` reaches the end state in one migration. On
     * PostgreSQL it also rewrites every row and holds ACCESS EXCLUSIVE while it does, which blocks
     * readers as well as writers. On a small table that is seconds and the sequence below is
     * overkill; on a large one it is an outage. **The size at which that flips is a fact about the
     * table that nothing here can read**, so the payload carries the sequence that is safe at any
     * size and names the shortcut in a precondition, where it is a choice the reader makes with
     * what they know rather than a default this package picked for them.
     *
     * ## No downtime class, and every step its own migration
     *
     * A `schema_object` payload has no deploy whose effect a downtime class could describe, and the
     * validator refuses one here rather than rendering it. For the same reason no step may claim
     * `this_migration`: the fix for a state IS a new migration.
     */
    public function remediationForObject(SchemaObject $object): ?RemediationPayload
    {
        if ($object->type !== SchemaObjectType::Table) {
            return null;
        }

        // Only where this rule actually FLAGGED, which is narrower than "said something". Asking
        // the rule rather than re-deriving the test here: two conditions for one question drift
        // the day the rule narrows its subject.
        //
        // ⚠️ AN UNDETERMINED VERDICT MUST NOT CARRY MATERIAL, AND THE FIRST VERSION OF THIS LET IT.
        // A table whose only mismatched pair had one end the catalog could not read is reported as
        // undetermined -- the question was asked and not answered. A considered `none` beside that
        // reads as "here is what to do about the thing I just said I could not decide", which is
        // the one way a fix template is worse than none at all. The concern that serves every other
        // catalog rule filters exactly this way; this rule builds its own payload and had to say so
        // itself. Found by the coverage floor rather than by a test, which is its own lesson.
        $flagged = array_filter(
            $this->judgeSchemaObject($object),
            static fn (RuleVerdict $verdict): bool => ! $verdict->isPass
                && ! $verdict->isUndetermined()
                && ! $verdict->notApplicableReason instanceof NotApplicableReason,
        );

        if ($flagged === []) {
            return null;
        }

        $widenable = $this->widenablePairs($object);

        if ($widenable === []) {
            return new NoSafeSequenceTemplate()->payload(
                $this->noSequenceReasonKey($object),
                'sqlens::messages.remediation.no_safe_sequence.schema_decision_state_verification',
                $this->id(),
                null,
                RemediationSubject::SchemaObject,
            );
        }

        return new RemediationPayload(
            steps: [
                new RemediationStep(
                    order: 1,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: 'sqlens::messages.remediation.expand_contract.expand',
                    sqlTemplate: 'ALTER TABLE {{table}} ADD COLUMN {{new_column}} bigint',
                ),
                new RemediationStep(
                    order: 2,
                    kind: RemediationStepKind::QueuedJob,
                    noteKey: 'sqlens::messages.remediation.expand_contract.backfill',
                ),
                new RemediationStep(
                    order: 3,
                    kind: RemediationStepKind::ManualGate,
                    noteKey: 'sqlens::messages.remediation.expand_contract.dual_write',
                ),
                new RemediationStep(
                    order: 4,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: 'sqlens::messages.remediation.expand_contract.swap_the_key',
                    // Two statements, one migration. A table with the constraint on NEITHER column
                    // accepts rows that reference nothing, and the width of that window is the whole
                    // risk of this step. No RENAME here: on PostgreSQL that is its own form of ALTER
                    // TABLE and cannot ride along with the others, and the new column keeping its own
                    // name is what the release above already reads.
                    sqlTemplate: 'ALTER TABLE {{table}} DROP CONSTRAINT {{constraint}}; '
                        .'ALTER TABLE {{table}} ADD CONSTRAINT {{constraint}} '
                        .'FOREIGN KEY ({{new_column}}) REFERENCES {{referenced_table}} ({{referenced_column}})',
                ),
                new RemediationStep(
                    order: 5,
                    kind: RemediationStepKind::SeparateMigration,
                    noteKey: 'sqlens::messages.remediation.expand_contract.contract',
                    sqlTemplate: 'ALTER TABLE {{table}} DROP COLUMN {{old_column}}',
                ),
            ],
            strategy: RemediationStrategy::ExpandContract,
            ruleId: $this->id(),
            // No downtime class: a state finding has no deploy to describe, and the validator
            // refuses a payload that carries one here.
            preconditions: [
                'sqlens::messages.remediation.expand_contract.precondition.in_place_rewrites_the_table',
                'sqlens::messages.remediation.expand_contract.precondition.no_old_version_running',
                'sqlens::messages.remediation.expand_contract.precondition.release_boundary_available',
            ],
            verification: 'sqlens::messages.remediation.expand_contract.verification',
            subject: RemediationSubject::SchemaObject,
        );
    }

    /**
     * The foreign-key pairs on this table that a standard sequence can widen.
     *
     * Two exclusions, and both are the rule declining rather than failing to notice. A constraint
     * carrying more than one column pair is composite, and its columns cannot be taken one at a
     * time. A pair whose referencing side is the WIDER one is the mirror finding: matching those
     * means moving the parent, which is a different act on a different table.
     *
     * @return list<array{constraint: string, local: string, localType: ?string, far: string, farType: ?string}>
     */
    private function widenablePairs(SchemaObject $object): array
    {
        $pairs = ImplicitCast::pairs($object);

        $perConstraint = [];

        foreach ($pairs as $pair) {
            $perConstraint[$pair['constraint']] = ($perConstraint[$pair['constraint']] ?? 0) + 1;
        }

        $widenable = [];

        foreach ($pairs as $pair) {
            if (($perConstraint[$pair['constraint']] ?? 0) !== 1) {
                continue;
            }

            if ($pair['localType'] === null || $pair['farType'] === null) {
                continue;
            }

            $local = ImplicitCast::integerWidth($pair['localType']);
            $far = ImplicitCast::integerWidth($pair['farType']);

            if ($local === null || $far === null || $local >= $far) {
                continue;
            }

            $widenable[] = $pair;
        }

        return $widenable;
    }

    /**
     * Which conclusion this rule reached about a table it flagged but has no sequence for.
     *
     * Read off the pairs rather than defaulted, because the three reasons are genuinely different
     * advice and a reader acts on each differently. The composite case is checked first: a table
     * carrying both a composite mismatch and a non-integer one is more usefully told about the
     * composite, which is the one with a mechanical answer waiting on a decision.
     */
    private function noSequenceReasonKey(SchemaObject $object): string
    {
        $pairs = ImplicitCast::pairs($object);
        $perConstraint = [];

        foreach ($pairs as $pair) {
            $perConstraint[$pair['constraint']] = ($perConstraint[$pair['constraint']] ?? 0) + 1;
        }

        $parentIsNarrower = false;

        foreach ($pairs as $pair) {
            if ($pair['localType'] === null || $pair['farType'] === null) {
                continue;
            }

            if (ImplicitCast::sameType($pair['localType'], $pair['farType'], self::EQUIVALENT)) {
                continue;
            }

            if (($perConstraint[$pair['constraint']] ?? 0) > 1) {
                return 'sqlens::messages.remediation.no_safe_sequence.type_mismatch_composite_key';
            }

            $local = ImplicitCast::integerWidth($pair['localType']);
            $far = ImplicitCast::integerWidth($pair['farType']);

            if ($local !== null && $far !== null && $local > $far) {
                $parentIsNarrower = true;
            }
        }

        return $parentIsNarrower
            ? 'sqlens::messages.remediation.no_safe_sequence.type_mismatch_parent_is_narrower'
            : 'sqlens::messages.remediation.no_safe_sequence.type_mismatch_not_an_integer_pair';
    }
}
