<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\DeclaresLimitations;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\StabilityTier;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * An index on `updated_at` that costs its table every HOT update.
 *
 * ## Why one index decides it for the whole table
 *
 * A HOT update writes the new row version on the same page and adds no index entry, but only while
 * no column that a non-summarizing index reads has changed. Laravel's `timestamps()` writes
 * `updated_at` on every `save()` that changes anything, so with an index on it no such update can be
 * HOT, however much room the page has: every update writes an entry into every index of the table
 * and leaves a dead one in each. `fillfactor` does not help. A BRIN index is summarizing and does
 * not block HOT, which is the control on the same column.
 *
 * Measured on PostgreSQL 18.0 over three tables of 10,000 rows with `fillfactor = 70`, each updated
 * once with `updated_at = now()`: no index on the column left 4,416 of the 10,000 updates HOT, a
 * BRIN index 4,416, a B-tree index none.
 *
 * ## Why this one is EXPERIMENTAL
 *
 * The weight comes from the table's update counters, which move with every write and can be reset,
 * so the verdict depends on when the audit asks. That is the tension `PG.L7.INDEX_UNUSED` names, and
 * it gets the same answer: a project that wants this question asks for it.
 *
 * ## What is read, and from where
 *
 * The index's key columns and expressions, its INCLUDE columns and its predicate, from `pg_index`
 * rather than from its name, and its access method. The counters are `n_tup_upd` and
 * `n_tup_hot_upd` of its table. A table that took fewer than 1,000 updates in the window pays almost
 * nothing, and one whose updates are mostly HOT anyway does not write `updated_at` on them.
 */
final class UpdatedAtIndexBlocksHotRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes, DeclaresLimitations
{
    /** Below this many updates in the window the table pays too little to be worth a finding. */
    private const int MIN_UPDATES = 1000;

    /** At or above this share of HOT updates the updates evidently do not write the column. */
    private const int HOT_SHARE_PERCENT = 80;

    /** The built-in access methods that summarize a range of pages, which no update has to write. */
    private const array SUMMARIZING_METHODS = ['brin'];

    /** @return non-empty-list<SchemaObjectType> */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Index];
    }

    public function id(): string
    {
        return 'PG.L7.UPDATED_AT_INDEX_BLOCKS_HOT';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    public function category(): Category
    {
        return Category::Performance;
    }

    #[Override]
    public function stability(): StabilityTier
    {
        return StabilityTier::Experimental;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Index) {
            return [];
        }

        $method = strtolower($object->getString('method') ?? '');

        if (in_array($method, self::SUMMARIZING_METHODS, true) || ! $this->readsUpdatedAt($object)) {
            return [];
        }

        if (! $object->hasAttribute('table_updates')) {
            return [RuleVerdict::undetermined(sprintf(
                'The update statistics of the table behind %s could not be read, so whether its updates '
                .'are HOT is unknown. That is not a pass: a role that cannot see pg_stat_all_tables and a '
                .'table whose updates are all HOT produce the same empty answer.',
                $object->qualifiedName,
            ), UndeterminedReason::StatisticsUnavailable)];
        }

        if ($object->getBool('index_stats_counting') === false) {
            return [RuleVerdict::undetermined(sprintf(
                'The update counters of the table behind %s were read, but this server hands new '
                .'connections track_counts = off, so its updates are not counted and no share of HOT '
                .'updates can be read from them. PG.L7.TRACK_COUNTS_OFF reports the setting itself.',
                $object->qualifiedName,
            ), UndeterminedReason::StatisticsUnavailable)];
        }

        $updates = $object->getInt('table_updates') ?? -1;
        $hot = $object->getInt('table_hot_updates') ?? -1;

        if ($updates < self::MIN_UPDATES || $hot < 0 || $hot * 100 >= self::HOT_SHARE_PERCENT * $updates) {
            return [];
        }

        $since = $object->getString('index_stats_reset_at') ?? '';

        return [RuleVerdict::flag(sprintf(
            '%s is a %s index that reads updated_at, which Laravel\'s timestamps write on every save, so '
            .'no update of its table that writes the column can be HOT. Of %d updates counted %s, %d '
            .'were HOT (%d%%): each of the others wrote an entry into every index of the table and left a '
            .'dead one in each, however much room the page had. Drop the index if nothing reads it '
            .'(PG.L7.INDEX_UNUSED answers that), or keep it on purpose. A BRIN index on the column does '
            .'not cost HOT, but it serves a range filter, not an ORDER BY.',
            $object->qualifiedName,
            $method === '' ? 'non-summarizing' : $method,
            $updates,
            $since === '' ? 'since the server started counting' : 'since '.$since,
            $hot,
            intdiv($hot * 100, $updates),
        ))];
    }

    /** @return list<string> */
    public function limitations(): array
    {
        return [
            'reads the share of HOT updates over the whole table: where most updates leave updated_at alone, the share stays at 80 percent or above and the index is not reported, although the updates that do write the column are not HOT',
            'counts the updates since the statistics were last reset, which moves between two audits of the same schema; that is why the rule is experimental',
        ];
    }

    /**
     * Whether the index reads `updated_at` in a key, an expression, an INCLUDE column or its predicate.
     *
     * Read from what `pg_index` holds, never from the index's name: `orders_updated_at_index` may
     * index another column, and an index named anything may read this one.
     */
    private function readsUpdatedAt(SchemaObject $index): bool
    {
        $include = preg_match('/\bINCLUDE \((.*?)\)/i', $index->getString('definition') ?? '', $match) === 1 ? $match[1] : '';

        $read = implode(' ', [
            $index->getString('key_columns') ?? '',
            $index->getString('expression') ?? '',
            $index->getString('predicate') ?? '',
            $include,
        ]);

        return preg_match('/(?<![A-Za-z0-9_])"?updated_at"?(?![A-Za-z0-9_])/i', $read) === 1;
    }
}
