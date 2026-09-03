<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Subjects\SubjectContext;
use Pushery\SQLens\Subjects\SubjectKind;

/**
 * The seam between the three subject sources (capture, live catalog, PHP
 * callsites) and the one rule engine. Every rule asks a subject three things:
 * what kind of origin it is, its stable identity (for location and dedupe), and
 * its injected context.
 *
 * Dispatch semantics a rule's appliesTo(Subject) must honor, documented here
 * because they are the whole point of the seam:
 *   - it is side-effect free, never throws, and touches no database;
 *   - a subject it does not apply to produces NO finding (no pass noise);
 *   - a subject it applies to but cannot evaluate produces an undetermined
 *     finding with a named reason.
 * "Not applicable" and "not evaluable" are two different things — collapsing
 * them turns a real skip into a silent non-match.
 */
interface Subject
{
    public function kind(): SubjectKind;

    /**
     * A stable identity for this subject, used to build a location and to
     * deduplicate findings. Same input state ⇒ same identity, so output is
     * reproducible.
     */
    public function identity(): string;

    public function context(): SubjectContext;
}
