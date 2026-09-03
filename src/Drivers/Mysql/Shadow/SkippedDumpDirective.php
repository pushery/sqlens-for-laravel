<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

/**
 * A statement from a `schema:dump` that is a client directive, not schema SQL, and
 * is therefore NOT replayed into the shadow database — recorded rather than
 * silently swallowed.
 *
 * A version-gated conditional comment such as `/*!40101 SET NAMES … *​/` sets
 * client session state (character set, collation, SQL mode) that the shadow
 * database has no need of; replaying it would at best be a no-op and at worst fail.
 * "No silent green" applies to the dump layer too: a directive dropped without a
 * word is indistinguishable from one the splitter simply missed, so each carries
 * the reason it was skipped.
 */
final readonly class SkippedDumpDirective
{
    public function __construct(
        public string $directive,
        public string $reason,
    ) {}
}
