<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The shipped rule registry is not usable as the contract's input.
 *
 * It exists so a broken generator cannot become a quiet contract change. The API-surface snapshot
 * is what the breaking-change gate diffs; an entry dropped from it because it could not be read
 * would remove a rule from the promised surface with no diff to notice — the failure that gate is
 * there to prevent, arriving through its own input.
 */
final class MalformedRuleRegistry extends RuntimeException {}
