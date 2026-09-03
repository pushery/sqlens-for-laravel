<?php

declare(strict_types=1);

namespace Pushery\SQLens\Canonical\Classification;

use Pushery\SQLens\Canonical\StatementKind;

/**
 * One recognizable statement shape: an ordered list of elements that, if they
 * match the leading tokens, assign a kind and capture the statement's targets.
 * A driver lists its signatures most-specific-first; the classifier applies them
 * in order and the first full match wins (so `ALTER TABLE … DROP COLUMN` is caught
 * before the generic `ALTER TABLE …` fallback).
 */
final readonly class StatementSignature
{
    /**
     * @param  list<SignatureElement>  $elements
     */
    public function __construct(
        public StatementKind $kind,
        public array $elements,
    ) {}
}
