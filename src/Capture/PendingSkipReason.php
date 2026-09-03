<?php

declare(strict_types=1);

namespace Pushery\SQLens\Capture;

use Pushery\SQLens\Findings\UndeterminedReason;

/**
 * Why the pending-migration resolver could not answer "which migrations are
 * pending" — a NAMED reason, never an empty list passed off as "nothing pending,
 * all clean".
 *
 * The empty pending list read as success is the single most dangerous shape this
 * layer can produce: a run that checked nothing looks exactly like a run that
 * found nothing wrong. So an unreachable connection, a missing migration table, or
 * an empty migration path is reported as an `undetermined` carrying one of these,
 * each of which maps to a reserved `LINT.SKIPPED.*` rule id so it reads the same
 * in a report and a baseline as any other finding.
 */
enum PendingSkipReason: string
{
    /** The connection could not be reached, so the pending set is unknown. */
    case ConnectionUnreachable = 'connection_unreachable';

    /** The connection is reachable but has no migration repository table yet. */
    case NoMigrationTable = 'no_migration_table';

    /** No migration path holds any migration file to resolve. */
    case EmptyMigrationPath = 'empty_migration_path';

    /** The reserved rule id this skip reports under. */
    public function ruleId(): string
    {
        return 'LINT.SKIPPED.'.match ($this) {
            self::ConnectionUnreachable => 'CONNECTION_UNREACHABLE',
            self::NoMigrationTable => 'NO_MIGRATION_TABLE',
            self::EmptyMigrationPath => 'EMPTY_MIGRATION_PATH',
        };
    }

    /**
     * The three-valued undetermined reason this skip carries into a finding. The
     * precise cause stays in the rule id and the message; this maps it onto the
     * fixed public reason axis so the run's per-reason counts stay meaningful.
     */
    public function undeterminedReason(): UndeterminedReason
    {
        return match ($this) {
            self::ConnectionUnreachable => UndeterminedReason::ServerUnreachable,
            self::NoMigrationTable, self::EmptyMigrationPath => UndeterminedReason::StructurallyNotApplicable,
        };
    }

    /** A one-line English explanation of why the pending set could not be resolved. */
    public function description(): string
    {
        return match ($this) {
            self::ConnectionUnreachable => 'The connection could not be reached, so which migrations are pending is unknown.',
            self::NoMigrationTable => 'The connection has no migration repository table yet, so the pending set could not be read.',
            self::EmptyMigrationPath => 'No migration path holds a migration file to resolve.',
        };
    }
}
