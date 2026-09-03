<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use LogicException;
use Pushery\SQLens\Deploy\DeployCheckCatalog;
use Pushery\SQLens\Deploy\DeployCheckMetadata;
use Pushery\SQLens\Findings\DowntimeClass;
use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Findings\Location;
use Pushery\SQLens\Findings\Result;
use Pushery\SQLens\Findings\UndeterminedReason;
use Pushery\SQLens\Subjects\SubjectContext;

/**
 * The comparison's result, as findings.
 *
 * ## Why the translation exists at all
 *
 * {@see DriftComparator} answers the question and {@see DriftReport} holds the answer, and neither
 * of them is something a person or a pipeline reads. Everything this package can do with a
 * result — the console grouping, the JSON envelope, GitHub annotations, SARIF, the baseline, the
 * severity axis, `downtime_class`, suppression — is defined over {@see Finding} and nothing else.
 *
 * So a drift report that stopped at its own value type would have arrived with a private shape and
 * lost all of it. `sqlens:drift` printed counts and blind-spot sentences, and its `--format` option
 * was declared in the signature and read nowhere: `--format=json` produced the same prose as the
 * default, which is worse than the option not existing.
 *
 * ## The metadata is READ from the catalog, never restated here
 *
 * Severity, level, category, stability, downtime class and the documentation URL all come from
 * {@see DeployCheckCatalog}. Writing them here as literals would put every one of them in two
 * places, and the catalog is the half a generated page and the `explain_rule` tool are built from —
 * so the drift a reader hit would be between the finding and the page describing it.
 *
 * A class whose id reaches no catalog row is a programming error rather than a runtime condition,
 * and it fails loudly here instead of shipping a finding with a dead link.
 */
final readonly class DriftFindings
{
    /** The id every blind spot reports under — the absence of a comparison, not one of its answers. */
    public const string UNCOMPARED_ID = 'DEPLOY.DRIFT.UNCOMPARED';

    /**
     * Every entry and every blind spot, as findings.
     *
     * Blind spots come SECOND in construction order and nowhere in sort order: {@see Result::of}
     * sorts by location, so where they land is decided there. What matters here is that they are
     * present at all — a caller that rendered only `entries` would print a clean bill of health this
     * run was never given.
     *
     * @return list<Finding>
     */
    public static function of(DriftReport $report, SubjectContext $context, string $connection): array
    {
        $findings = [];

        foreach ($report->entries as $entry) {
            $findings[] = self::entry($entry, $context, $connection);
        }

        foreach ($report->blindSpots as $blindSpot) {
            $findings[] = self::blindSpot($blindSpot, $context, $connection);
        }

        return $findings;
    }

    /** One disagreement, at one object. */
    private static function entry(DriftEntry $entry, SubjectContext $context, string $connection): Finding
    {
        $metadata = self::metadata($entry->class->ruleId());

        return Finding::fail(
            ruleId: $metadata->id,
            messagePrefix: $metadata->messagePrefix,
            message: self::message($entry),
            location: Location::inCatalog($context->driver, $connection, $entry->qualifiedName, $entry->type),
            category: $metadata->category,
            level: $metadata->level,
            stability: $metadata->stability,
            documentationUrl: $metadata->documentationUrl(),
            context: $context,
            severity: $metadata->severity,
        )
            ->withDowntimeClass($metadata->downtimeClass ?? DowntimeClass::Online)
            // The correction travels WITH the finding, because the reader's next question is always
            // the same one and the comparison already knows enough to answer it. It is material, not
            // an applied change: SQLens writes no migration file and runs no DDL.
            ->withRemediation(DriftCorrectionHint::for($entry));
    }

    /**
     * One object type, on one side, that could not be read.
     *
     * The location names the TYPE rather than an object, because there is no object to name — that
     * is the whole content of the finding. Using the type as the object name keeps the two sides of
     * a blind spot (`live` and `expected` on one type) distinguishable in the fingerprint through
     * the message, while leaving the location stable enough to baseline.
     */
    private static function blindSpot(DriftBlindSpot $blindSpot, SubjectContext $context, string $connection): Finding
    {
        $metadata = self::metadata(self::UNCOMPARED_ID);

        return Finding::undetermined(
            ruleId: $metadata->id,
            messagePrefix: $metadata->messagePrefix,
            message: ucfirst($blindSpot->message()).'.',
            reason: UndeterminedReason::DriftSideUnreadable,
            location: Location::inCatalog(
                $context->driver,
                $connection,
                $blindSpot->type->value.' ('.$blindSpot->side->value.' side)',
                $blindSpot->type,
            ),
            category: $metadata->category,
            level: $metadata->level,
            stability: $metadata->stability,
            documentationUrl: $metadata->documentationUrl(),
            context: $context,
            severity: $metadata->severity,
        )->withDowntimeClass($metadata->downtimeClass ?? DowntimeClass::Online);
    }

    /**
     * What a reader needs in order to act, without opening a connection.
     *
     * The attribute diff travels IN the sentence for the divergent class, because that is the class
     * whose finding is useless without it: "this column differs" sends its reader back to the two
     * databases to do the work the comparison already did.
     */
    private static function message(DriftEntry $entry): string
    {
        $subject = 'The '.$entry->type->value.' `'.$entry->qualifiedName.'` ';

        return match ($entry->class) {
            DriftClass::UnexpectedInDatabase => $subject
                .'exists in the database and no migration describes it. The next rebuild of this '
                .'schema from the migrations alone would not contain it. Write the migration that '
                .'creates it, or drop it deliberately — this run cannot say which is right, only '
                .'that the two sides disagree.',
            DriftClass::MissingInDatabase => $subject
                .'is described by the migrations and is not in the database. A migration that failed '
                .'and one that never ran leave exactly this, and the migration table is where that '
                .'is answered.',
            DriftClass::Divergent => $subject
                .'is present on both sides and described differently: '
                .self::changes($entry).'. Both sides are compared in their canonical form, so this '
                .'is a difference normalization did not erase.',
        };
    }

    /** The changed attributes, deterministically ordered, each carrying both sides. */
    private static function changes(DriftEntry $entry): string
    {
        $changes = $entry->changes;
        ksort($changes, SORT_STRING);

        $rendered = [];

        foreach ($changes as $attribute => $sides) {
            $rendered[] = $attribute.' is '.self::side($sides['live'])
                .' in the database and '.self::side($sides['expected']).' in the migrations';
        }

        // An empty diff would leave a sentence ending in a colon. The comparator does not produce a
        // divergence without one, so this is a guard against a future caller rather than a case
        // seen — and it says so rather than rendering an empty list as though nothing differed.
        return $rendered === [] ? 'the attributes that differ were not recorded' : implode('; ', $rendered);
    }

    private static function side(string|int|float|bool|null $value): string
    {
        return match (true) {
            $value === null => 'absent',
            is_bool($value) => $value ? '`true`' : '`false`',
            default => '`'.$value.'`',
        };
    }

    /**
     * The catalog row for an id, or a loud failure — never a finding with a dead link.
     *
     * The refusal shares its line with the lookup deliberately: it is unreachable while every
     * `DriftClass` id and {@see self::UNCOMPARED_ID} are cataloged, which `DriftFindingsTest` holds,
     * so an `if` here would be a branch no run can enter and the 100% floor would have to be bought
     * with an ignore annotation this repository does not use anywhere.
     */
    private static function metadata(string $id): DeployCheckMetadata
    {
        return self::rowsById()[$id] ?? throw new LogicException($id.' emits findings and is in no deploy catalog row, so its documentation url resolves to nothing.');
    }

    /** @return array<string, DeployCheckMetadata> */
    private static function rowsById(): array
    {
        $rows = [];

        foreach (DeployCheckCatalog::metadata() as $check) {
            $rows[$check->id] = $check;
        }

        return $rows;
    }
}
