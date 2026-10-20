<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Canonical\QuotedIdentifier;
use Pushery\SQLens\Catalog\Usage\KeyCounterProjection;
use Pushery\SQLens\Catalog\Usage\KeyCounterState;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\NarrowIntegerPrimaryKeyRule;
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
use Pushery\SQLens\Rules\DeclaresLimitations;
use Pushery\SQLens\Rules\Keys\KeyCounterFill;
use Pushery\SQLens\Rules\Keys\NarrowIntegerPrimaryKey;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A primary key whose sequence has used up a large share of what the key can hold.
 *
 * ## A type choice, and then a date
 *
 * {@see NarrowIntegerPrimaryKeyRule} reports every key that can run out, on its type alone and at
 * level 6, where a project asks to be told about type choices. That finding reads the same on a key
 * that has handed out four values and on one that has handed out two billion. This rule reads how
 * far the sequence has got, and once the key has used the configured share of its ceiling the type
 * choice has become a deadline, which is a level-5 question.
 *
 * ## The ceiling is the lower of two
 *
 * The column's type is one limit and the sequence's own maximum is the other. They differ more
 * often than they look: a `serial` column widened with `ALTER COLUMN ... TYPE bigint` keeps a
 * sequence `AS integer`, measured on PostgreSQL 18, and the insert after 2,147,483,647 fails with
 * "reached maximum value of sequence" although the column would hold the value. The finding names
 * whichever limit binds, because the two have different cures: widening the column rewrites the
 * table, while `ALTER SEQUENCE ... AS bigint` changes a default maximum without touching it.
 *
 * ## What it cannot read, and says so
 *
 * The position of a sequence is read beside the catalog. A role holding neither SELECT nor USAGE on
 * the sequence gets NULL for it, the same NULL a sequence that has never handed out a value returns,
 * and `pg_monitor` is such a role. That is reported as undetermined with the grant that answers it,
 * never as an empty key. A key with no sequence behind it, filled by the application, is outside
 * what this rule can read without reading the table's rows, which an audit does not do.
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
        return 'PG.L5.PK_NEAR_CEILING';
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
            'a key filled by the application rather than by a sequence has no counter to read, and its fill is '
            .'not judged, because that would mean reading the table\'s rows',
            'with CACHE above 1 the position read is the last value the sequence reserved, which can stand '
            .'ahead of the last value an insert used',
        ];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $key = NarrowIntegerPrimaryKey::integerKey($object);

        if ($key === null) {
            return [];
        }

        $state = $object->getString('key_counter');

        // No sequence that can run out stands behind this key, or it has not handed out a value yet.
        // Both are answers the reading gave, and neither is a key near its ceiling.
        if ($state === KeyCounterProjection::NONE || $state === KeyCounterState::Unused->value) {
            return [];
        }

        $sequence = $object->getString('key_counter_source') ?? 'its sequence';

        if ($state === KeyCounterState::Withheld->value) {
            return [RuleVerdict::undetermined(sprintf(
                'How far %s, the sequence behind the primary key of %s, has got could not be read: the role '
                .'reading the catalog holds neither SELECT nor USAGE on it, and PostgreSQL answers such a role '
                .'with NULL, the same answer it gives for a sequence that has never handed out a value. GRANT '
                .'SELECT ON SEQUENCE %s to the audit role lets it read the position and nothing else; it '
                .'cannot draw a value.',
                $sequence,
                $object->qualifiedName,
                $sequence,
            ), UndeterminedReason::MissingPrivilege)];
        }

        $used = $object->getInt('key_counter_value');

        if ($state !== KeyCounterState::Read->value || $used === null) {
            $failure = $object->getString('key_counter_failure');

            return [RuleVerdict::undetermined(sprintf(
                'How far the sequence behind the primary key of %s has got could not be read%s, so whether '
                .'the key is close to its ceiling is unknown. That is not a pass: a key nobody could look '
                .'at and a key with room to spare produce the same silence.',
                $object->qualifiedName,
                $failure === null || $failure === '' ? '' : ' ('.$failure.')',
            ), UndeterminedReason::CatalogReadFailed)];
        }

        $sequenceBinds = $this->sequenceBinds($object, $key['type']);
        $ceiling = $sequenceBinds ? $object->getInt('key_counter_ceiling') : KeyCounterFill::columnCeiling($key['type'], false);

        if ($ceiling === null || ! KeyCounterFill::reaches($used, $ceiling, $this->minPercentUsed)) {
            return [];
        }

        if ($sequenceBinds) {
            return [RuleVerdict::flag(sprintf(
                '%s has used %s of the %s values %s can hand out for its primary key on %s, %s of its '
                .'ceiling. The %s column would hold more: the limit is the sequence\'s own maximum, and when '
                .'the sequence reaches it every INSERT into the table fails. ALTER SEQUENCE %s AS %s raises '
                .'a maximum that was the default of a narrower type without rewriting the table; a maximum '
                .'set by hand needs NO MAXVALUE in the same statement.',
                $object->qualifiedName,
                KeyCounterFill::grouped($used),
                KeyCounterFill::grouped($ceiling),
                $sequence,
                $key['column'],
                KeyCounterFill::percent($used, $ceiling),
                $key['type'],
                $sequence,
                $key['type'],
            ))];
        }

        return [RuleVerdict::flag(sprintf(
            '%s has used %s of the %s values its %s primary key on %s can hold, %s of its ceiling. When '
            .'%s reaches the end, every INSERT into the table fails, and widening the key then rewrites the '
            .'table and every index over it under a lock, on a table that is large by then. Plan the change '
            .'while there is room: widen the key to bigint and the referencing foreign-key columns in the '
            .'same change, and check that the sequence follows. An identity column widens its sequence '
            .'with it; a serial column keeps a sequence AS integer until ALTER SEQUENCE %s AS bigint.',
            $object->qualifiedName,
            KeyCounterFill::grouped($used),
            KeyCounterFill::grouped($ceiling),
            $key['type'],
            $key['column'],
            KeyCounterFill::percent($used, $ceiling),
            $sequence,
            $sequence,
        ))];
    }

    /**
     * The fix material for a key this rule reported, and which one depends on the limit it reaches.
     *
     * Where the sequence's own maximum is the limit, the column already holds more, and one statement
     * reaches the end state without touching the table: `ALTER SEQUENCE … AS` the column's type. That
     * is `rewrite_avoidance`, in a single step.
     *
     * Where the column's type is the limit, a considered `none`. Widening a primary key moves every
     * column that references it, and which columns those are and the order they move in is a schema
     * decision rather than a statement; the narrower-key and near-ceiling rules judge those columns
     * one by one. Nothing for a table this rule did not flag, and nothing for an undetermined verdict.
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

        $type = NarrowIntegerPrimaryKey::integerKey($object)['type'] ?? null;

        if (! $this->sequenceBinds($object, $type)) {
            return new NoSafeSequenceTemplate()->payload(
                'sqlens::messages.remediation.no_safe_sequence.key_near_ceiling',
                'sqlens::messages.remediation.no_safe_sequence.key_near_ceiling_verification',
                $this->id(),
                null,
                RemediationSubject::SchemaObject,
            );
        }

        $step = new RemediationStep(
            order: 1,
            kind: RemediationStepKind::SeparateMigration,
            noteKey: 'sqlens::messages.remediation.rewrite_avoidance.widen_the_sequence',
            sqlTemplate: 'ALTER SEQUENCE {{sequence}} AS {{type}}',
        );

        return new RemediationPayload(
            steps: [$step->filled(['sequence' => $this->quotedSequence($object), 'type' => (string) $type])],
            strategy: RemediationStrategy::RewriteAvoidance,
            ruleId: $this->id(),
            preconditions: ['sqlens::messages.remediation.rewrite_avoidance.precondition.maximum_set_by_hand'],
            verification: 'sqlens::messages.remediation.rewrite_avoidance.sequence_verification',
            subject: RemediationSubject::SchemaObject,
        );
    }

    /** Whether the sequence's own maximum, rather than the column's type, is the ceiling the key reaches. */
    private function sequenceBinds(SchemaObject $object, ?string $type): bool
    {
        $columnCeiling = $type === null ? null : KeyCounterFill::columnCeiling($type, false);
        $sequenceCeiling = $object->getInt('key_counter_ceiling');

        return $sequenceCeiling !== null && $sequenceCeiling > 0
            && ($columnCeiling === null || $sequenceCeiling < $columnCeiling);
    }

    /**
     * The sequence behind the key, quoted as PostgreSQL reads it. Empty when the sequence lives in
     * another schema than the table, which leaves its placeholder standing for the reader to fill
     * rather than guessing where the schema's name ends.
     */
    private function quotedSequence(SchemaObject $object): string
    {
        $schema = (string) $object->parent;
        $sequence = (string) $object->getString('key_counter_source');

        if (! str_starts_with($sequence, $schema.'.')) {
            return '';
        }

        return QuotedIdentifier::of('"', $schema, substr($sequence, strlen($schema) + 1));
    }
}
