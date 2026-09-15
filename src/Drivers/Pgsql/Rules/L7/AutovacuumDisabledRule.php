<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L7;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Drivers\Pgsql\Deploy\FreezeHorizonCheck;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A table somebody switched autovacuum off for.
 *
 * `ALTER TABLE … SET (autovacuum_enabled = false)` is a real and sometimes correct decision: a table
 * loaded in bulk on a schedule is vacuumed better at a chosen moment than at an arbitrary one. What
 * makes it worth a finding is that the decision outlives the reason, and nothing else in the
 * database mentions it again.
 *
 * ## Two consequences, and the second one is not optional
 *
 * **The estimates stop meaning anything.** A table without autovacuum accumulates dead rows, so its
 * file size says the least about the rows a rewrite really has to copy — and the size is what every
 * time and space statement of a deploy rests on. The row estimate goes stale for the same reason:
 * autovacuum is also what triggers most `ANALYZE` runs.
 *
 * **The server takes it back anyway.** Autovacuum being off does not stop the freeze horizon. When a
 * table crosses `autovacuum_freeze_max_age` the server starts an anti-wraparound vacuum on it
 * REGARDLESS of this parameter — and that worker does not yield to a lock request. So the setting
 * does not avoid the vacuum; it defers it to a moment nobody chose, and makes the one that comes
 * larger. {@see FreezeHorizonCheck} is the deploy-time half of the same fact.
 *
 * ## Why it is a FINDING and not a refusal
 *
 * A table maintained by hand — vacuumed in a window, deliberately, by somebody who knows why — is a
 * legitimate shape, and this rule cannot see the cron that does it. That is a false positive by
 * construction, and the answer is an `ignore` entry with the reason beside it rather than a
 * heuristic in this class guessing at intent from a name or a size.
 *
 * ## No MySQL twin
 *
 * InnoDB has no per-table equivalent. Its purge and its adaptive flushing are server-wide, and the
 * nearest table-level knob — `STATS_AUTO_RECALC` — decides whether the optimizer's statistics are
 * refreshed, not whether dead rows are reclaimed. A rule registered there would be a different
 * finding wearing this one's name.
 */
final class AutovacuumDisabledRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /** The server's own spelling for the parameter being off, read out of the storage parameters. */
    private const string DISABLED = 'false';

    /**
     * Tables only — a run that read none produced no subject for this rule, and the report has to be
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
        return 'PG.L7.AUTOVACUUM_DISABLED';
    }

    public function level(): Level
    {
        return Level::PerformanceHeuristics;
    }

    /**
     * Performance, not safety: nothing is lost or corrupted. What degrades is the space the table
     * occupies and the worth of every estimate taken from it — and classifying that as safety would
     * put it in the band a project gates its deploys on.
     */
    public function category(): Category
    {
        return Category::Performance;
    }

    /** @return list<Suite> */
    public function suites(): array
    {
        // Audit only, and structurally: a storage parameter lives in the catalog, and a migration
        // that sets one says nothing about the tables it did not touch. The lint suite would answer
        // about one table per run and stay silent about the schema, which is the wrong shape for a
        // finding whose whole point is that somebody set this and forgot.
        return [Suite::Audit];
    }

    /** @return list<RuleVerdict> */
    public function judgeSchemaObject(SchemaObject $object): array
    {
        if ($object->type !== SchemaObjectType::Table) {
            return [];
        }

        // Three states, and only one of them is this finding. An empty value is a table with no such
        // parameter — running under the cluster's setting — and reading that as "off" would report
        // every table in the schema.
        if ($object->getString('autovacuum_enabled') !== self::DISABLED) {
            return [];
        }

        return [RuleVerdict::flag(sprintf(
            'Autovacuum is switched off on %s (`autovacuum_enabled = false`). Dead rows are not '
            .'reclaimed, so the table grows and its file size stops saying anything about the rows a '
            .'rewrite would copy — which is what every time and space statement about a deploy rests '
            .'on. Its row estimate goes stale for the same reason: autovacuum is what triggers most '
            .'ANALYZE runs. And the setting does not avoid the vacuum, it defers it: when the table '
            .'crosses autovacuum_freeze_max_age the server starts an anti-wraparound vacuum on it '
            .'anyway, that worker does not yield to a lock request, and by then there is more to do. '
            .'If this table really is maintained by hand, say so with an ignore entry and the reason '
            .'beside it — this check cannot see the schedule that does it.',
            $object->getString('logical_name') ?? $object->qualifiedName,
        ), $object->qualifiedName, $object->type)];
    }
}
