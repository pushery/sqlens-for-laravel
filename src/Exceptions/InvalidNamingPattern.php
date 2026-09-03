<?php

declare(strict_types=1);

namespace Pushery\SQLens\Exceptions;

use RuntimeException;

/**
 * The naming rule was handed a pattern PCRE cannot compile.
 *
 * A USER misconfiguration, like {@see InvalidAnalyseConfiguration}, and it throws for the same
 * reason — but the failure it prevents is sharper than a silent switch-off, because the silent
 * alternative here is a silent switch-ON.
 *
 * `preg_match()` answers `false` for a pattern it cannot compile, not `0`. The check that reads it
 * asks `!== 1`, and `false !== 1` is true — so a single typo in a project's pattern turns the rule
 * from "this identifier does not match" into "**every** identifier is a violation". Measured before
 * this class existed, with `/^[a-z/` as the pattern:
 *
 *     violates('orders')  →  true
 *
 * `orders` is the canonical GOOD name in this rule's own default. A project would meet a report
 * accusing every table it owns, with no hint that its own configuration is the cause.
 *
 * The mirror case is just as bad and depends only on which way the comparison is written: an
 * `=== 0` check would answer "nothing violates" and switch the rule off entirely. Neither reading
 * of `false` is defensible, which is why it is refused rather than interpreted.
 */
final class InvalidNamingPattern extends RuntimeException
{
    /**
     * PCRE refused the pattern.
     *
     * The reason is PCRE's own sentence — "missing terminating ] for character class at offset 5" —
     * rather than `preg_last_error_msg()`, which answers "Internal error" for a compilation failure
     * and tells a reader nothing about where to look.
     */
    public static function unusable(string $pattern, string $reason): self
    {
        return new self(sprintf(
            'The identifier naming pattern %s cannot be compiled: %s. Every identifier would be '
            .'reported as a violation, so the run stops here instead — a rule that accuses '
            .'everything is indistinguishable from a project that names everything wrongly.',
            $pattern === '' ? '(empty)' : '"'.$pattern.'"',
            $reason,
        ));
    }
}
