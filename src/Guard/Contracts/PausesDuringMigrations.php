<?php

declare(strict_types=1);

namespace Pushery\SQLens\Guard\Contracts;

/**
 * An inspector that stands still while the migrator runs in the process it watches.
 *
 * An application may run migrations itself, from a job or a request: `Artisan::call('migrate')` when it
 * rebuilds a database, a tenant migration started from a screen. The process is a watched one, but the
 * statements are migrations. The migrator announces both ends of its run, `MigrationsStarted` before the
 * first migration and `MigrationsEnded` after the last, on the way up and on the way down.
 *
 * ## Why it extends AccumulatesPerWindow
 *
 * `MigrationsEnded` is not dispatched from a `finally`. A migration that fails throws past it, and the end
 * never comes. A pause that waited for it alone would stay on for the rest of a worker's life, over every
 * job that follows, and a guardrail that says nothing looks exactly like an application with nothing to
 * say. So the next request, job or command ends a pause too, through {@see AccumulatesPerWindow::startWindow()},
 * and the type makes that second end impossible to leave out.
 */
interface PausesDuringMigrations extends AccumulatesPerWindow
{
    /** The migrator is about to run its first migration. */
    public function migrationsStarted(): void;

    /** The migrator ran its last migration. */
    public function migrationsEnded(): void;
}
