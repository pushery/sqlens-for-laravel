<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy\Drift;

use Pushery\SQLens\Catalog\Canonical\CatalogObjectFingerprint;
use Pushery\SQLens\Catalog\CatalogSkip;
use Pushery\SQLens\Catalog\CatalogSnapshot;
use Pushery\SQLens\Subjects\SchemaObject;
use Pushery\SQLens\Subjects\SchemaObjectType;

/**
 * Two readings of one schema, compared — the database as it is against what the migrations say it
 * should be.
 *
 * ## It compares CANONICAL readings, and that is a type-level promise rather than a hope
 *
 * The only way in is a {@see CatalogSnapshot}, which is what a catalog reader produces and what the
 * canonicalizer has already been through — a reader runs it as it reads. There is no entry point
 * that takes raw rows, so "compare without canonicalizing" is not a mistake this class can be asked
 * to make. It matters more here than anywhere else in the package: two readings of an UNCHANGED
 * database differ in quoting, type aliases and default spelling every single time, and a comparison
 * over that reports drift on every object and teaches its reader to stop reading the report.
 *
 * ## What it does not do, deliberately
 *
 * It opens no connection, runs no query and writes nothing. It is given two readings and returns a
 * value. That keeps the most dangerous operation in this package — looking at production while a
 * deploy is in flight — in exactly one place, the reader, where its session bounds and its
 * read-only seal live.
 *
 * Roles, grants and server settings are not compared. They are real drift and they matter, but they
 * are the audit and security suites' subject, and a comparator that reached into them would produce
 * two tools' findings under one id. The boundary is stated here rather than left as a silent hole.
 */
final readonly class DriftComparator
{
    /**
     * @param  CatalogSnapshot  $live  the database as it is
     * @param  CatalogSnapshot  $expected  what the migration state says it should be
     */
    public function compare(CatalogSnapshot $live, CatalogSnapshot $expected): DriftReport
    {
        $liveObjects = $this->index($live);
        $expectedObjects = $this->index($expected);

        $entries = [];

        foreach ($liveObjects as $identity => $object) {
            if (! isset($expectedObjects[$identity])) {
                $entries[] = new DriftEntry(
                    DriftClass::UnexpectedInDatabase,
                    $object->type,
                    $object->qualifiedName,
                    attributes: CatalogObjectFingerprint::comparableAttributes($object),
                );

                continue;
            }

            // The fingerprint answers "did this object move at all" in one comparison, over the
            // canonical form and with the volatile attributes already excluded. Only when it says
            // yes is the attribute-by-attribute diff worth building — which is the whole reason the
            // per-object hash exists rather than a whole-snapshot one.
            $counterpart = $expectedObjects[$identity];

            if (CatalogObjectFingerprint::of($object) === CatalogObjectFingerprint::of($counterpart)) {
                continue;
            }

            $entries[] = new DriftEntry(
                DriftClass::Divergent,
                $object->type,
                $object->qualifiedName,
                changes: $this->changes($object, $counterpart),
            );
        }

        foreach ($expectedObjects as $identity => $object) {
            if (! isset($liveObjects[$identity])) {
                $entries[] = new DriftEntry(
                    DriftClass::MissingInDatabase,
                    $object->type,
                    $object->qualifiedName,
                    attributes: CatalogObjectFingerprint::comparableAttributes($object),
                );
            }
        }

        usort($entries, static fn (DriftEntry $a, DriftEntry $b): int => $a->sortKey() <=> $b->sortKey());

        return new DriftReport($entries, $this->blindSpots($live, $expected));
    }

    /**
     * Both readings' objects, keyed by identity.
     *
     * Identity carries the TYPE as well as the name, so a table and a view of the same name are two
     * objects rather than one that changed kind — which is what a name-only key would report, and
     * it would be wrong in the most confusing possible way.
     *
     * @return array<string, SchemaObject>
     */
    private function index(CatalogSnapshot $snapshot): array
    {
        $indexed = [];

        foreach ($snapshot->objects as $object) {
            if ($this->belongsToTheDatabaseRatherThanTheSchema($object)) {
                continue;
            }

            $indexed[$object->identity()] = $object;
        }

        ksort($indexed);

        return $indexed;
    }

    /**
     * An object whose identity is the DATABASE, not the schema — excluded from the comparison.
     *
     * One member so far: PostgreSQL's database-scoped collation, which `pg_database` names after the
     * database itself. It is the same boundary the class docblock draws around roles, grants and
     * server settings, and it is drawn here for a sharper reason: on the two sides of a drift run
     * that object CANNOT match, ever. The live side is the real database and the expectation side is
     * a throwaway one, so the names differ by construction.
     *
     * Measured 2026-08-18, on the first run of `sqlens:drift` against a real server: every run
     * produced two findings nobody can act on —
     *
     *     DEPLOY.DRIFT.UNEXPECTED_IN_DATABASE  collation `sqlens_test`
     *     DEPLOY.DRIFT.MISSING_IN_DATABASE     collation `sqlens_drift_20260818200915_2d56cb1a`
     *
     * — and the second one carries a timestamp, so two runs over an unchanged database produced
     * different reports. That is both halves of what would have killed the feature: a false finding
     * on every run, and a report that never diffs clean.
     *
     * It is excluded rather than normalized because there is nothing true to say about it here. The
     * collation is chosen at `CREATE DATABASE` and no migration can change it, so a comparison
     * against a replay cannot report on it in either direction. Its VERSION drift is a real check
     * and it keeps its home in the audit suite, which reads one database and does not have this
     * problem.
     */
    private function belongsToTheDatabaseRatherThanTheSchema(SchemaObject $object): bool
    {
        return $object->type === SchemaObjectType::Collation
            && ($object->attributes()['collation_scope'] ?? null) === 'database';
    }

    /**
     * The attributes that differ, each with both sides.
     *
     * The union of both key sets rather than one side's: an attribute PRESENT on one side and
     * absent on the other is a difference, and walking only the live side would miss every
     * attribute the migration state has and the database does not.
     *
     * @return array<string, array{live: scalar|null, expected: scalar|null}>
     */
    private function changes(SchemaObject $live, SchemaObject $expected): array
    {
        $liveAttributes = CatalogObjectFingerprint::comparableAttributes($live);
        $expectedAttributes = CatalogObjectFingerprint::comparableAttributes($expected);

        $changes = [];

        foreach (array_keys($liveAttributes + $expectedAttributes) as $attribute) {
            $onLive = $liveAttributes[$attribute] ?? null;
            $onExpected = $expectedAttributes[$attribute] ?? null;

            if ($onLive !== $onExpected) {
                $changes[$attribute] = ['live' => $onLive, 'expected' => $onExpected];
            }
        }

        ksort($changes);

        return $changes;
    }

    /**
     * Every object type either side failed to read, with the side it failed on.
     *
     * Both sides, separately, because they fail for different reasons and the fix differs: the live
     * side is a real database with real privileges, the expected side is a replay the tool built
     * itself. Merging them would leave a reader unable to tell "grant the audit role more" from
     * "the replay did not finish".
     *
     * @return list<DriftBlindSpot>
     */
    private function blindSpots(CatalogSnapshot $live, CatalogSnapshot $expected): array
    {
        $spots = [];

        foreach ([DriftSide::Live->value => $live, DriftSide::Expected->value => $expected] as $side => $snapshot) {
            foreach ($snapshot->gaps() as $gap) {
                $spot = new DriftBlindSpot($gap->type, DriftSide::from($side), $this->reason($gap));
                $spots[$spot->sortKey()] = $spot;
            }
        }

        ksort($spots);

        return array_values($spots);
    }

    /** The named reason out of a skip — never an empty string, because a reason is the point. */
    private function reason(CatalogSkip $gap): string
    {
        return $gap->detail ?? $gap->reason->value;
    }
}
