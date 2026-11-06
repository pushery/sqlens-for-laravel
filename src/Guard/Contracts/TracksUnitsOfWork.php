<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Contracts;

/**
 * An inspector that pauses during migrations and follows the jobs and Artisan commands of its process.
 *
 * A migration can start a job or a command itself. A job it dispatches onto a synchronous queue runs inside
 * the migration, and so does a command it calls with `Artisan::call()`. Their start opens no new window: it is
 * part of the migrator's run, and a pause that ended there would report every statement of the migrations
 * that follow. So an inspector that follows units hears a job or a command begin through unitStarted()
 * instead of {@see AccumulatesPerWindow::startWindow()}, and its end through unitEnded().
 *
 * The end of a unit is also how a pause ends that the migrator never ended. A migration that fails throws past
 * `MigrationsEnded`, but the job or the command that ran the migrator still ends, with its exception or its
 * exit code, and with it the run it started. The end of a request ends every run, through startWindow().
 *
 * A command that runs the migrator begins the run itself. Right after its unitStarted(), an inspector that
 * follows units hears migrationsStarted() as well, so the run covers the whole command: the migrator's own
 * table that `migrate` creates before `MigrationsStarted`, the tables `migrate:fresh` drops first, and a
 * `--seed` after the last migration. The end of the command ends that run through unitEnded().
 */
interface TracksUnitsOfWork extends PausesDuringMigrations
{
    /**
     * A job or an Artisan command began in this process.
     *
     * @param  object|null  $unit  what its start and its end share, the job or the command's input, or null
     *                             for an event dispatched by its name alone
     */
    public function unitStarted(?object $unit): void;

    /**
     * A job or an Artisan command ended, by finishing or by throwing.
     *
     * @param  object|null  $unit  the object its start named
     */
    public function unitEnded(?object $unit): void;
}
