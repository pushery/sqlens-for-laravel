<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Capture\CaptureRun;
use Pushery\SQLens\Capture\CaptureSection;
use Pushery\SQLens\Capture\PendingMigration;
use Pushery\SQLens\Capture\Shadow\ShadowSession;

/**
 * Runs the real migration against a provisioned shadow database and captures the
 * SQL it emits — the truth-mode counterpart to intercepting a pretend log.
 *
 * It is a seam, not the implementation: the concrete runner listens on the shadow
 * connection while a real `migrate` executes, canonicalizes each statement, and
 * produces the SAME `CaptureRun` shape the pretend path does — because the whole
 * point of the two modes is one result form, not two. Keeping it behind an
 * interface lets the `ShadowCaptor` orchestrate guard, provision, run and teardown
 * without knowing how the capture itself works, and lets that orchestration be
 * tested with a fake runner and no database.
 */
interface ShadowRunner
{
    /**
     * Migrate the given already-resolved, already-ordered migrations against the
     * shadow database the session names, and return the captured run.
     *
     * @param  iterable<PendingMigration>  $migrations
     */
    public function captureFrom(ShadowSession $session, iterable $migrations, CaptureSection $section): CaptureRun;
}
