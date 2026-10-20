<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Rules\L6;

use Override;
use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Findings\Confidence;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A column named for an instant still to come, held in MySQL's `TIMESTAMP`.
 *
 * ## The type ends in 2038, and a future value gets there first
 *
 * `TIMESTAMP` stores seconds since 1970 and holds nothing after 2038-01-19 03:14:07 UTC. In strict
 * mode a later value is refused with error 1292: measured on MySQL 8.0.36, 2038-01-19 03:14:07 went
 * in and 2041-10-18 00:00:00 did not. Every `TIMESTAMP` column reaches that date in time, but one
 * that holds future instants reaches it now: an expiry fifteen years ahead is refused today. Laravel's
 * `timestamp()`, `timestamps()` and `softDeletes()` all declare `TIMESTAMP` on MySQL.
 *
 * ## A heuristic on the column name
 *
 * Nothing in a catalog says which instants a column holds, so the name decides, segment by segment.
 * A word that points ahead is the evidence, and its past form is not: `expires_at` and `ends_at` are
 * reported, `expired_at` and `ended_at` are not. `created_at`, `updated_at` and `deleted_at` hold the
 * past and carry no such word, which keeps `timestamps()` and `softDeletes()` silent.
 *
 * Read from the catalog rather than from a migration, like the other rules about a column's type: a
 * lint run sees the pending migrations, and a column created years ago carries its type in the
 * catalog and in no pending migration.
 */
final class FutureInstantInTimestampRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
    /**
     * The name segments that point at an instant still to come.
     *
     * A past form says the instant has happened, so none is listed: `expires`, not `expired`. The
     * one exception is `scheduled`, which names an instant set for later.
     *
     * @var list<string>
     */
    private const array FUTURE_SEGMENTS = [
        'expires', 'expire', 'expiry', 'expiration', 'until', 'due', 'deadline', 'ends', 'starts',
        'scheduled', 'available', 'publish', 'renews', 'next', 'retry', 'remind',
    ];

    /**
     * Tables only, and a run that read none produced no subject for this rule, which the report
     * says rather than letting the silence read as a clean answer.
     *
     * @return non-empty-list<SchemaObjectType>
     */
    public function judgedObjectTypes(): array
    {
        return [SchemaObjectType::Table];
    }

    public function id(): string
    {
        return 'MY.L6.TIMESTAMP_2038';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    public function category(): Category
    {
        return Category::Idiom;
    }

    /** Heuristic: the catalog says which type a column has, and only its name says what it holds. */
    #[Override]
    public function confidence(): Confidence
    {
        return Confidence::Heuristic;
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

        $columns = [];

        foreach (ForeignKeyIndexCoverage::parse($object->getString('column_types') ?? '') as $column => $types) {
            if (mb_strtolower($types[0] ?? '') === 'timestamp' && $this->pointsAhead((string) $column)) {
                $columns[] = (string) $column;
            }
        }

        if ($columns === []) {
            return [];
        }

        sort($columns);

        return [RuleVerdict::flag(sprintf(
            'On %s, %s named for an instant still to come but held as TIMESTAMP: %s. MySQL\'s TIMESTAMP '
            .'holds nothing after 2038-01-19 03:14:07 UTC, and in strict mode a later value is refused '
            .'with error 1292, so an expiry or a schedule set past that date fails today, years before '
            .'every TIMESTAMP column reaches it. DATETIME holds instants up to 9999-12-31. It stores the '
            .'value it is given, without the conversion from the session time zone that TIMESTAMP makes, '
            .'so the session has to run in UTC; $table->dateTime() and $table->dateTimeTz() declare it. '
            .'The rule reads the column name, so a %s that never holds a future instant can stay as it is. '
            .'Changing the type rewrites the table; the lint suite classifies that operation and carries '
            .'its downtime class.',
            $object->qualifiedName,
            count($columns) === 1 ? 'a column is' : count($columns).' columns are',
            implode(', ', $columns),
            count($columns) === 1 ? 'column' : 'column among them',
        ))];
    }

    /** Whether a column name carries a segment that points at an instant still to come. */
    private function pointsAhead(string $column): bool
    {
        return array_intersect(explode('_', mb_strtolower($column)), self::FUTURE_SEGMENTS) !== [];
    }
}
