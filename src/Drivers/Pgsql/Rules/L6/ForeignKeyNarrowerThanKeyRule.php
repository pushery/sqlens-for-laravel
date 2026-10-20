<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\ForeignKeyWideningTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\L9\TypeImplicitCastRule;
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
 * A foreign key whose referencing column is a narrower integer than the key it references.
 *
 * ## The failure is dated
 *
 * An `int` column referencing a `bigint` key can only ever point at the first 2^31 of its target's
 * 2^63 values. Nothing about the schema says so, and every test passes, because a test database
 * never gets there. Then the parent sequence crosses 2,147,483,647, years after the migration, and
 * every insert into the child fails with an out-of-range error naming a column nobody connects to a
 * foreign key.
 *
 * That is the failure `PG.L6.PK_NOT_BIGINT` reports at the primary key, and this rule sits beside it
 * on the same level for that reason. The case here is the quieter one: the parent was given the
 * right width, and only the column pointing at it was not.
 *
 * ## The usual reason for it is false, and that was measured
 *
 * The common argument is that the mismatched pair stops using the index. Against PostgreSQL 18.4 it
 * does not: `EXPLAIN SELECT * FROM k1 WHERE pid = 42::bigint` over an `int` column answers
 * `Index Scan … Index Cond: (pid = '42'::bigint)`, because the btree integer operator family carries
 * cross-type operators. The finding names the date, never the index.
 *
 * Every other mismatch between the two ends of a key stays with {@see TypeImplicitCastRule} on level
 * 9: a key wider than what it references, and two types that are not two widths of one number.
 *
 * ## Audit only, and that is structural
 *
 * A migration adding a foreign key carries the type of neither column, and the referenced table was
 * almost always created by a migration that is no longer pending. The catalog is the only place both
 * ends exist at once.
 */
final class ForeignKeyNarrowerThanKeyRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, ProvidesSchemaObjectRemediation
{
    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'PG.L6.FK_NARROWER_THAN_KEY';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    /** Idiom, like `PG.L6.PK_NOT_BIGINT`: the same ceiling, met one table further along. */
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
                // An end the reading did not establish, beside one that leaves room for a narrower
                // integer. Not a pass: a reading that lost a column must not make the key look fine.
                if ($this->mayNarrow($pair['localType'], $pair['farType'])) {
                    $unread[] = $pair['constraint'].' ('.$pair['local'].' → '.$pair['far'].')';
                }

                continue;
            }

            if (ImplicitCast::narrowerInteger($pair['localType'], $pair['farType'])) {
                $offenders[] = $this->sentence($pair['local'], $pair['localType'], $pair['far'], $pair['farType']);
            }
        }

        // One verdict per table: results are deduplicated by rule and location, and a catalog finding
        // is located at its table, so a second verdict about the same table would be dropped.
        if ($offenders !== []) {
            sort($offenders, SORT_STRING);

            return [RuleVerdict::flag(implode(' ', $offenders), $object->qualifiedName, $object->type)];
        }

        if ($unread !== []) {
            sort($unread, SORT_STRING);

            return [RuleVerdict::undetermined(
                'One end of these foreign keys was not read, and the other leaves room for a narrower integer, '
                .'so whether the key can address all of what it references is unknown rather than fine: '
                .implode(', ', $unread).'.',
                UndeterminedReason::CatalogReadFailed,
            )];
        }

        return [];
    }

    /**
     * The fix material for a narrowing key that stands alone on its constraint.
     *
     * Its end state is no judgment call: the child has to be as wide as what it references. The
     * sequence is expand/contract, every step its own migration: add a `bigint` column beside the old
     * one, backfill it from a job, ship a release that writes both and reads the new one, move the
     * constraint, and only then drop the old column.
     *
     * `ALTER TABLE … ALTER COLUMN … TYPE bigint` reaches the same end state in one statement, and on
     * a small table it is the better choice. It is named in a precondition rather than emitted,
     * because on PostgreSQL it rewrites every row and holds `ACCESS EXCLUSIVE` while it does, and the
     * size at which that stops being acceptable is a fact about the table that nothing here can read.
     *
     * A composite key gets a considered `none`: its columns cannot be widened one at a time without
     * deciding an order, and each `ALTER` takes its own exclusive lock. No downtime class either, and
     * no step in a migration at hand: a state finding has no deploy to describe, and its fix is a new
     * migration.
     */
    public function remediationForObject(SchemaObject $object): ?RemediationPayload
    {
        if ($object->type !== SchemaObjectType::Table) {
            return null;
        }

        // Only where this rule flagged. An undetermined verdict carries no material: "here is what
        // to do about the thing I just said I could not decide" is worse than no template at all.
        $flagged = array_filter(
            $this->judgeSchemaObject($object),
            static fn (RuleVerdict $verdict): bool => ! $verdict->isPass
                && ! $verdict->isUndetermined()
                && ! $verdict->notApplicableReason instanceof NotApplicableReason,
        );

        if ($flagged === []) {
            return null;
        }

        if (! $this->hasWidenablePair($object)) {
            return new NoSafeSequenceTemplate()->payload(
                'sqlens::messages.remediation.no_safe_sequence.type_mismatch_composite_key',
                'sqlens::messages.remediation.no_safe_sequence.schema_decision_state_verification',
                $this->id(),
                null,
                RemediationSubject::SchemaObject,
            );
        }

        return new ForeignKeyWideningTemplate()->payload($this->id(), $object);
    }

    private function sentence(string $local, string $localType, string $far, string $farType): string
    {
        return sprintf(
            '`%s` is `%s` and references `%s`, which is `%s`. The narrower side can only ever point at the '
            .'first %s of the wider one\'s values, so this key stops working the day the referenced sequence '
            .'passes that number — long after the migration that set it up. Widen `%s` to `%s`.',
            $local, $localType, $far, $farType,
            number_format((2 ** ((int) ImplicitCast::integerWidth($localType) * 8 - 1)) - 1),
            $local, $farType,
        );
    }

    /** Whether a narrowing pair of this table stands alone on its constraint, so it can be widened by itself. */
    private function hasWidenablePair(SchemaObject $object): bool
    {
        $pairs = ImplicitCast::pairs($object);
        $perConstraint = [];

        foreach ($pairs as $pair) {
            $perConstraint[$pair['constraint']] = ($perConstraint[$pair['constraint']] ?? 0) + 1;
        }

        foreach ($pairs as $pair) {
            if ($pair['localType'] === null || $pair['farType'] === null) {
                continue;
            }

            if ($perConstraint[$pair['constraint']] === 1 && ImplicitCast::narrowerInteger($pair['localType'], $pair['farType'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether an end that was not read could hide a narrower integer: both ends unread, a read
     * referencing side narrower than `bigint`, or a read referenced side wider than `smallint`.
     */
    private function mayNarrow(?string $local, ?string $far): bool
    {
        if ($local !== null) {
            $width = ImplicitCast::integerWidth($local);

            return $width !== null && $width < 8;
        }

        if ($far !== null) {
            $width = ImplicitCast::integerWidth($far);

            return $width !== null && $width > 2;
        }

        return true;
    }
}
