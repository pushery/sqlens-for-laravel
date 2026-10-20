<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L5;

use Pushery\SQLens\Catalog\Usage\KeyCounterProjection;
use Pushery\SQLens\Catalog\Usage\KeyCounterState;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Drivers\Mysql\Rules\L6\NarrowIntegerPrimaryKeyRule;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Remediation\NoSafeSequenceTemplate;
use Pushery\SQLens\Remediation\RemediationSubject;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\DeclaresLimitations;
use Pushery\SQLens\Rules\Keys\KeyCounterFill;
use Pushery\SQLens\Rules\Keys\NarrowIntegerPrimaryKey;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A primary key whose AUTO_INCREMENT has used up a large share of what the key can hold.
 *
 * ## A type choice, and then a date
 *
 * {@see NarrowIntegerPrimaryKeyRule} reports every key narrower than `BIGINT`, on its type alone and
 * at level 6. That finding reads the same on a key that has handed out four values and on one that
 * has handed out four billion. This rule reads the next AUTO_INCREMENT value, and once the key has
 * used the configured share of its ceiling the type choice has become a deadline, which is a level-5
 * question.
 *
 * ## The ceiling is the column's, signed or unsigned
 *
 * MySQL's AUTO_INCREMENT has no maximum of its own: it stops where the column's type stops. The
 * signedness is read from the catalog, because Laravel's `increments()` produces `INT UNSIGNED`,
 * which reaches 4,294,967,295 rather than 2,147,483,647. Measured on MySQL 8.0.36, the insert after
 * the ceiling fails with a duplicate-key error on the primary key, error 1062.
 *
 * ## Read fresh, or not at all
 *
 * The value comes from `SHOW CREATE TABLE`, read beside the catalog. `information_schema.TABLES`
 * carries the same column from a statistics cache that can be a day old, and a key judged against a
 * stale number would be judged against a table that no longer exists. A value that could not be
 * read is reported as undetermined, never as a key with room to spare.
 */
final class PrimaryKeyNearCeilingRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, DeclaresLimitations, ProvidesSchemaObjectRemediation
{
    private readonly int $minPercentUsed;

    /**
     * @param  int|null  $minPercentUsed  the share of its ceiling a key may use before it is reported,
     *                                    from `sqlens.audit.key_ceiling.min_percent_used`. Null is
     *                                    the shipped default.
     */
    public function __construct(string $projectRoot, ?int $minPercentUsed = null)
    {
        parent::__construct($projectRoot);

        $this->minPercentUsed = $minPercentUsed ?? KeyCounterFill::DEFAULT_MIN_PERCENT_USED;
    }

    /**
     * Tables only. A run that read none produced no subject for this rule, and the report has to be
     * able to say so rather than let the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'MY.L5.PK_NEAR_CEILING';
    }

    public function level(): Level
    {
        return Level::SchemaBasics;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<string> */
    public function limitations(): array
    {
        return [
            'a key without AUTO_INCREMENT, filled by the application, has no counter to read, and its fill is '
            .'not judged, because that would mean reading the table\'s rows',
        ];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $key = NarrowIntegerPrimaryKey::of($object);

        if ($key === null) {
            return [];
        }

        $state = $object->getString('key_counter');

        // No AUTO_INCREMENT stands behind this key, or it has not handed out a value yet. Both are
        // answers the reading gave, and neither is a key near its ceiling.
        if ($state === KeyCounterProjection::NONE || $state === KeyCounterState::Unused->value) {
            return [];
        }

        $used = $object->getInt('key_counter_value');

        if ($state !== KeyCounterState::Read->value || $used === null) {
            $failure = $object->getString('key_counter_failure');

            return [RuleVerdict::undetermined(sprintf(
                'The next AUTO_INCREMENT value of %s could not be read%s, so whether its primary key is close '
                .'to its ceiling is unknown. That is not a pass: a key nobody could look at and a key with '
                .'room to spare produce the same silence.',
                $object->qualifiedName,
                $failure === null || $failure === '' ? '' : ' ('.$failure.')',
            ), UndeterminedReason::CatalogReadFailed)];
        }

        $ceiling = KeyCounterFill::columnCeiling($key['type'], $key['unsigned']);

        if ($ceiling === null || ! KeyCounterFill::reaches($used, $ceiling, $this->minPercentUsed)) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            '%s has used %s of the %s values its %s%s primary key on %s can hold, %s of its ceiling. When '
            .'AUTO_INCREMENT reaches the end, every INSERT into the table fails with a duplicate-key error, '
            .'and widening the key then rewrites the table and every index over it, on a table that is large '
            .'by then. Plan the change while there is room: widen the key to BIGINT UNSIGNED and the '
            .'referencing foreign-key columns in the same change.',
            $object->qualifiedName,
            KeyCounterFill::grouped($used),
            KeyCounterFill::grouped($ceiling),
            strtoupper($key['type']),
            $key['unsigned'] ? ' UNSIGNED' : '',
            $key['column'],
            KeyCounterFill::percent($used, $ceiling),
        ))];
    }

    /**
     * A considered `none` for a key this rule reported.
     *
     * Widening the key is the cure, and it has no standard sequence: on MySQL a foreign key has to
     * carry exactly the type of the column it references, so the key and every column that references
     * it change together, and which columns those are and how the tables are rebuilt is a schema
     * decision rather than a statement. Nothing for a table this rule did not flag, and nothing for an
     * undetermined verdict.
     */
    public function remediationForObject(SchemaObject $object): ?RemediationPayload
    {
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
            'sqlens::messages.remediation.no_safe_sequence.key_near_ceiling_mysql',
            'sqlens::messages.remediation.no_safe_sequence.key_near_ceiling_verification',
            $this->id(),
            null,
            RemediationSubject::SchemaObject,
        );
    }
}
