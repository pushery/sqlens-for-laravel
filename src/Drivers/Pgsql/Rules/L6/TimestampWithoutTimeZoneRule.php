<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L6;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Contracts\DeclaresJudgedObjectTypes;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\AbstractCatalogRule;
use Pushery\SQLens\Rules\Coverage\ForeignKeyIndexCoverage;
use Pushery\SQLens\Rules\RuleVerdict;
use Pushery\SQLens\Rules\Suite;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * A timestamp column with no time zone — a moment stored without saying which clock it is on.
 *
 * ## What actually goes wrong
 *
 * `timestamp without time zone` stores the digits somebody handed it and nothing else. Two rows
 * written a second apart by workers in different regions are stored as if they happened an hour
 * apart, and nothing in the column says so. The value survives a dump, a restore onto a server with
 * another `TimeZone`, and a read replica in a third — unchanged, and meaning something different
 * each time.
 *
 * `timestamptz` does not store a zone either. It stores the INSTANT: PostgreSQL converts the value
 * to UTC on the way in using the session's zone and back out again on the way out. Two moments a
 * second apart stay a second apart, whoever wrote them and wherever they are read.
 *
 * The failure is quiet, which is why it is worth a rule. Nothing errors, nothing is corrupted at
 * write time, and the mistake surfaces months later as a report that is off by an hour twice a year
 * — around a daylight-saving boundary, on rows written by one region.
 *
 * ## The exception this rule does not know about
 *
 * A wall-clock time that is deliberately zone-less is a legitimate use: a shop that opens at 09:00
 * local time opens at 09:00 in every branch, and converting that to an instant would be the bug.
 * Laravel's own `timestamps()` are not that case, but a business-hours or recurring-appointment
 * column may be — so the finding is an idiom recommendation at level 6, and the documentation names
 * the exception rather than pretending it does not exist.
 */
final class TimestampWithoutTimeZoneRule extends AbstractCatalogRule implements DeclaresJudgedObjectTypes
{
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

    /**
     * The canonical types this rule speaks about.
     *
     * `time without time zone` is included for the same reason and with the same caveat — a time of
     * day with no date has no instant to be converted to, so it is the weaker case, and the message
     * says which of the two it found.
     *
     * @var list<string>
     */
    private const array ZONELESS = ['timestamp without time zone', 'time without time zone'];

    public function id(): string
    {
        return 'PG.L6.TIMESTAMP_NO_TZ';
    }

    public function level(): Level
    {
        return Level::TypeIdiom;
    }

    /**
     * Idiom, not safety, and the boundary is worth stating.
     *
     * The consequence can be a genuine data error, which argues for safety. But the column is not
     * WRONG — it is under-specified, and whether that matters depends on what the application puts
     * in it, which this rule cannot see. Filed under safety it would gate deploys on a judgment
     * about somebody else's domain.
     */
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

        foreach (ForeignKeyIndexCoverage::parse($object->getString('column_types') ?? '') as $column => $types) {
            $type = strtolower($types[0] ?? '');

            if (in_array($type, self::ZONELESS, true)) {
                $offenders[(string) $column] = $type;
            }
        }

        // ONE verdict naming every offending column, not one verdict per column.
        //
        // A catalog finding is located at the OBJECT, and results are deduplicated by rule id and
        // location — so a rule emitting one verdict per column would have all but the first
        // silently dropped. A reader would then see a single column named, fix it, and believe the
        // table was done. Naming them together is both correct here and more useful: "these three
        // columns" is one decision about one table, not three.
        return $offenders === [] ? [] : [RuleVerdict::flag($this->message($object, $offenders))];
    }

    /** @param  array<string, string>  $offenders  column name => the zone-less type it carries */
    private function message(SchemaObject $object, array $offenders): string
    {
        ksort($offenders);

        $named = implode(', ', array_map(
            static fn (string $type, string $column): string => $column.' ('.$type.')',
            $offenders,
            array_keys($offenders),
        ));

        // The recommendation follows the kind found. A time of day has no date and therefore no
        // instant to convert to, so `timetz` is its counterpart — recommending `timestamptz` for it
        // would be advice that does not compile.
        $replacement = array_any($offenders, static fn (string $type): bool => str_starts_with($type, 'timestamp'))
            ? 'timestamptz'
            : 'timetz';

        return sprintf(
            'On %s: %s carry no time zone, so they store the digits they were handed and no clock to read '
            .'them against. Two rows '
            .'written a second apart from different regions are stored an hour apart, and nothing in the '
            .'column says so; the value survives a restore onto a server with another TimeZone unchanged and '
            .'meaning something else. %s stores the INSTANT instead — converted to UTC on the way in and back '
            .'on the way out — so a moment stays the same moment wherever it is read. Deliberate wall-clock '
            .'columns are the exception: a branch that opens at 09:00 local opens at 09:00 everywhere, and '
            .'converting that would be the mistake.',
            $object->qualifiedName,
            $named,
            $replacement,
        );
    }
}
