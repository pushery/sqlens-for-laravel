<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L5;

use Pushery\SQLens\Catalog\Usage\KeyCounterState;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Contracts\ProvidesSchemaObjectRemediation;
use Pushery\SQLens\Drivers\Pgsql\Remediation\ForeignKeyWideningTemplate;
use Pushery\SQLens\Drivers\Pgsql\Rules\L6\ForeignKeyNarrowerThanKeyRule;
use Pushery\SQLens\Findings\NotApplicableReason;
use Pushery\SQLens\Findings\RemediationPayload;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\DeclaresLimitations;
use Pushery\SQLens\Rules\Keys\KeyCounterFill;
use Pushery\SQLens\Rules\Pedantic\ImplicitCast;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A foreign-key column narrower than the key it references, whose parent has nearly filled it.
 *
 * ## The column runs out before the key does
 *
 * {@see ForeignKeyNarrowerThanKeyRule} reports an `integer` column pointing at a `bigint` key on its
 * types alone, at level 6. The parent's own key has room for nine quintillion values, so nothing
 * about the parent looks wrong; the child column fails the first INSERT that points at a parent row
 * past 2,147,483,647. That day is decided by the parent's sequence, and this rule reads how far it
 * has got. Once the parent has used the configured share of the child column's ceiling, the type
 * mismatch has become a deadline, which is a level-5 question.
 *
 * ## What it reads
 *
 * The position of the sequence behind each referenced key is read beside the catalog and joined
 * onto the referencing table as `key_counter_references`. A referenced key is read when a narrower
 * single-column foreign key points at it, even where the key itself could never run out.
 *
 * One verdict per table: the finding names every column past the share, with the parent, its
 * sequence and the share each has used.
 */
final class ForeignKeyNearCeilingRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, DeclaresLimitations, ProvidesSchemaObjectRemediation
{
    private readonly int $minPercentUsed;

    /**
     * @param  int|null  $minPercentUsed  the share of the column's ceiling the parent may use before
     *                                    the column is reported, from
     *                                    `sqlens.audit.key_ceiling.min_percent_used`. Null is the
     *                                    shipped default.
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
        return 'PG.L5.FK_NEAR_CEILING';
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
            'a referenced key filled by the application rather than by a sequence has no counter to read, '
            .'and the column pointing at it is not judged',
            'a referenced table outside the audited schemas is not read, so a column pointing into it is '
            .'not judged',
        ];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        $narrowing = array_values(array_filter(
            ImplicitCast::pairs($object),
            static fn (array $pair): bool => $pair['localType'] !== null
                && $pair['farType'] !== null
                && ImplicitCast::narrowerInteger($pair['localType'], $pair['farType']),
        ));

        if ($narrowing === []) {
            return [];
        }

        if (! $object->hasAttribute('key_counter_references')) {
            $failure = $object->getString('key_counter_failure');

            return [RuleVerdict::undetermined(sprintf(
                'How far the sequences behind the keys %s references have got could not be read%s, so '
                .'whether its narrower foreign-key columns are close to their ceiling is unknown. That is '
                .'not a pass: a column nobody could measure and a column with room to spare produce the '
                .'same silence.',
                $object->qualifiedName,
                $failure === null || $failure === '' ? '' : ' ('.$failure.')',
            ), UndeterminedReason::CatalogReadFailed)];
        }

        $references = ForeignKeyIndexCoverage::parse($object->getString('key_counter_references') ?? '');
        $offending = [];
        $withheld = [];
        $unread = [];

        foreach ($narrowing as $pair) {
            [$state, $value, $sequence] = [...($references[$pair['local']] ?? []), '', '', ''];

            if ($state === KeyCounterState::Withheld->value) {
                $withheld[] = $sequence;

                continue;
            }

            if ($state === KeyCounterState::Unread->value) {
                $unread[] = $sequence;

                continue;
            }

            $ceiling = KeyCounterFill::columnCeiling((string) $pair['localType'], false);

            if ($state !== KeyCounterState::Read->value || ! is_numeric($value) || $ceiling === null
                || ! KeyCounterFill::reaches((int) $value, $ceiling, $this->minPercentUsed)) {
                continue;
            }

            $offending[] = sprintf(
                '%s (%s) references %s, whose sequence %s has handed out %s of the %s values the column can '
                .'hold (%s)',
                $pair['local'],
                $pair['localType'],
                $pair['far'],
                $sequence,
                KeyCounterFill::grouped((int) $value),
                KeyCounterFill::grouped($ceiling),
                KeyCounterFill::percent((int) $value, $ceiling),
            );
        }

        if ($offending !== []) {
            return [RuleVerdict::flag(sprintf(
                '%s has foreign-key columns narrower than the keys they reference, and those keys have '
                .'nearly filled them: %s. Every INSERT into %s that points at a parent row past the '
                .'column\'s ceiling fails, while the parent\'s own key still has room. Widen each column to '
                .'the type of the key it references while there is room; PG.L6.FK_NARROWER_THAN_KEY carries '
                .'the expand/contract sequence that does it without a long lock.',
                $object->qualifiedName,
                implode('; ', $offending),
                $object->qualifiedName,
            ))];
        }

        if ($withheld !== []) {
            $sequences = implode(', ', array_values(array_unique($withheld)));

            return [RuleVerdict::undetermined(sprintf(
                'How far %s, behind the keys the narrower foreign-key columns of %s reference, has got could '
                .'not be read: the role reading the catalog holds neither SELECT nor USAGE on it, and '
                .'PostgreSQL answers such a role with NULL, the same answer it gives for a sequence that has '
                .'never handed out a value. GRANT SELECT ON SEQUENCE %s to the audit role lets it read the '
                .'position and nothing else; it cannot draw a value.',
                $sequences,
                $object->qualifiedName,
                $sequences,
            ), UndeterminedReason::MissingPrivilege)];
        }

        if ($unread !== []) {
            return [RuleVerdict::undetermined(sprintf(
                'How far %s, behind the keys the narrower foreign-key columns of %s reference, has got could '
                .'not be read, so whether those columns are close to their ceiling is unknown.',
                implode(', ', array_values(array_unique($unread))),
                $object->qualifiedName,
            ), UndeterminedReason::CatalogReadFailed)];
        }

        return [];
    }

    /**
     * The fix material for a column this rule reported: widen it to the key it references.
     *
     * The same change {@see ForeignKeyNarrowerThanKeyRule} hands out for the same column, and from the
     * same sequence, because the deadline this rule reads changes when the work has to happen, never
     * what the work is. Only single-column keys reach this rule, so the composite case that rule
     * answers with `none` does not arise here.
     *
     * Nothing for a table this rule did not flag, and nothing for an undetermined verdict: material
     * for a position nobody could read would be advice about a column that may have room to spare.
     */
    public function remediationForObject(SchemaObject $object): ?RemediationPayload
    {
        $flagged = array_filter(
            $this->judgeSchemaObject($object),
            static fn (RuleVerdict $verdict): bool => ! $verdict->isPass
                && ! $verdict->isUndetermined()
                && ! $verdict->notApplicableReason instanceof NotApplicableReason,
        );

        return $flagged === [] ? null : new ForeignKeyWideningTemplate()->payload($this->id(), $object);
    }
}
