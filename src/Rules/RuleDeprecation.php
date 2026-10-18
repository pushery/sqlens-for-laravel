<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules;

use Pushery\SQLens\Audit\AuditNotices;

/**
 * The governance contract "rules are deprecated (no-op + notice), never
 * deleted", cast into a type before the first rule exists.
 *
 * Orthogonal to StabilityTier: a rule can be stable AND deprecated, so this is
 * its own field, not a fourth tier value. Rule::deprecation() returns null for
 * a non-deprecated rule — a deliberate statement, not a default to forget.
 *
 * The audit reports a deprecated rule as withheld, with its successor
 * ({@see AuditNotices::withheldByDeprecation()}). This is the
 * marker that notice, the registry and the metadata property test consume.
 */
final readonly class RuleDeprecation
{
    /**
     * @param  string  $since  The SQLens SemVer from which the rule is deprecated.
     * @param  string|null  $replacedBy  The rule id of the successor, if any. A
     *                                   deprecated rule id is never recycled; this
     *                                   points at the successor, it does not replace it.
     */
    public function __construct(
        public string $since,
        public ?string $replacedBy = null,
    ) {}
}
