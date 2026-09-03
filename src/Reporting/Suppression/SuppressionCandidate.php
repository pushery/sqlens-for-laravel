<?php

declare(strict_types=1);

namespace Pushery\SQLens\Reporting\Suppression;

use Pushery\SQLens\Findings\Finding;
use Pushery\SQLens\Reporting\Baseline\FindingFingerprint;
use Pushery\SQLens\Subjects\MigrationSql;

/**
 * A finding offered to the suppression chain, together with what the three layers
 * need in order to answer.
 *
 * These extras do not live on the Finding on purpose. The fingerprint needs the
 * CANONICAL excerpt, and the annotation layer needs the migration subject itself
 * — both are held by the pipeline that produced the finding, and putting them on
 * every Finding would push canonicalization and reflection into places that have
 * no business with either.
 *
 * A candidate that carries neither a fingerprint nor a subject is still valid: it
 * simply cannot be covered by the layers that need them, and the config layer can
 * still answer.
 */
final readonly class SuppressionCandidate
{
    public function __construct(
        public Finding $finding,
        public ?FindingFingerprint $fingerprint = null,
        public int $ordinal = 0,
        public ?MigrationSql $subject = null,
    ) {}
}
