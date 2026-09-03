<?php

declare(strict_types=1);

namespace Pushery\SQLens\Remediation;

/**
 * WHERE a step belongs — which is the part a reader most often gets wrong.
 *
 * The difference between "in this migration" and "in a separate one" is the difference between a
 * sequence that works and one that deadlocks on its own transaction. Naming it per step is what
 * lets an agent place the work instead of pasting everything into the file it already had open.
 */
enum RemediationStepKind: string
{
    /** A statement inside the migration being fixed. */
    case MigrationStatement = 'migration_statement';

    /** A statement that must run in a migration of its own, after this one has committed. */
    case SeparateMigration = 'separate_migration';

    /** Work that belongs in a queued job because it is unbounded in time. */
    case QueuedJob = 'queued_job';

    /** A session setting that must be in force before the statements that follow it. */
    case SessionSetting = 'session_setting';

    /** A point where a person decides — a deploy window, a confirmation, a backup. */
    case ManualGate = 'manual_gate';
}
