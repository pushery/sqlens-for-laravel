<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L9;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\ForeignKeyNarrowerThanKeyRule;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
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
 * ## The reason is not the one everybody gives, and that was measured
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
 * ## The dated case has a rule of its own
 *
 * An `int` column referencing a `bigint` key breaks the day the parent sequence passes
 * 2,147,483,647, years after the migration. That case is reported a level earlier, by
 * {@see ForeignKeyNarrowerThanKeyRule}, next to the narrow primary key it resembles. What stays here
 * is the rest: a key wider than what it references, and two types that are not two widths of one
 * number. Each is a conversion the schema did not intend.
 *
 * ## Audit only, and that is structural
 *
 * A migration adding a foreign key carries the type of neither column — the types live in the
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
     * `typstorage` for `text` and `varchar`. `bpchar` is deliberately not in the group: it pads to
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

            // Reported on level 6 by PG.L6.FK_NARROWER_THAN_KEY, so a project at level 9 reads it once.
            if (ImplicitCast::narrowerInteger($pair['localType'], $pair['farType'])) {
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
        return sprintf(
            '`%s` is `%s` and references `%s`, which is `%s`. PostgreSQL compares them by converting one side, '
            .'which the schema did not ask for and nothing records. Declare both ends as the same type.',
            $pair['local'], $pair['localType'], $pair['far'], $pair['farType'],
        );
    }

    /**
     * The fix material for the shapes this rule reports: a considered `none` for each.
     *
     * The one shape with a standard sequence, a single-column key whose referencing side is a
     * narrower integer, moved to {@see ForeignKeyNarrowerThanKeyRule} with that sequence. What remains
     * has no end state that can be decided without the application, so this rule looked and states
     * a conclusion rather than a null. A composite key cannot be widened one column at a time without
     * deciding an order. A pair where the PARENT is the narrower side points the other way: matching
     * them means widening the referenced key, and narrowing the child to fit would cement the smaller
     * ceiling. A non-integer pair, a timestamp against a date, has an answer per pair that depends on
     * which side is telling the truth about the data.
     *
     * A `schema_object` payload carries no downtime class: it has no deploy whose effect one could
     * describe, and the validator refuses one here rather than rendering it.
     */
    public function remediationForObject(SchemaObject $object): ?RemediationPayload
    {
        if ($object->type !== SchemaObjectType::Table) {
            return null;
        }

        // Only where this rule actually flagged, which is narrower than "said something". Asking
        // the rule rather than re-deriving the test here: two conditions for one question drift
        // the day the rule narrows its subject.
        //
        // An undetermined verdict must not carry material. A table whose only mismatched pair had
        // one end the catalog could not read is reported as undetermined -- the question was asked
        // and not answered. A considered `none` beside that would read as "here is what to do about
        // the thing I just said I could not decide", which is the one way a fix template is worse
        // than none at all.
        $flagged = array_filter(
            $this->judgeSchemaObject($object),
            static fn (RuleVerdict $verdict): bool => ! $verdict->isPass
                && ! $verdict->isUndetermined()
                && ! $verdict->notApplicableReason instanceof NotApplicableReason,
        );

        if ($flagged === []) {
            return null;
        }

        return new NoSafeSequenceTemplate()->payload(
            $this->noSequenceReasonKey($object),
            'sqlens::messages.remediation.no_safe_sequence.schema_decision_state_verification',
            $this->id(),
            null,
            RemediationSubject::SchemaObject,
        );
    }

    /**
     * Which conclusion this rule reached about a table it flagged.
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

            if (ImplicitCast::sameType($pair['localType'], $pair['farType'], self::EQUIVALENT)
                || ImplicitCast::narrowerInteger($pair['localType'], $pair['farType'])) {
                continue;
            }

            if ($perConstraint[$pair['constraint']] > 1) {
                return 'sqlens::messages.remediation.no_safe_sequence.type_mismatch_composite_key';
            }

            if (ImplicitCast::narrowerInteger($pair['farType'], $pair['localType'])) {
                $parentIsNarrower = true;
            }
        }

        return $parentIsNarrower
            ? 'sqlens::messages.remediation.no_safe_sequence.type_mismatch_parent_is_narrower'
            : 'sqlens::messages.remediation.no_safe_sequence.type_mismatch_not_an_integer_pair';
    }
}
