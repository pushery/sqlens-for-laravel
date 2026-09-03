<?php

declare(strict_types=1);

namespace Pushery\SQLens\Config;

/**
 * Where a rule id that has to be validated came from. Naming the origin is the
 * whole point of the check: "unknown rule id PG.L2.CONCURENTLY" sends someone
 * hunting through three files, while "in sqlens.ignore.2.rule" does not.
 */
enum RuleIdOrigin: string
{
    case ConfigIgnore = 'config';

    case Baseline = 'baseline';

    case Annotation = 'annotation';

    /**
     * The audit's own ignore list — a separate origin from the lint one on purpose.
     *
     * They are different files' worth of decisions about different subjects, and a message that
     * called both "the ignore list" would send somebody to the wrong block. A lint rule id written
     * into the audit list is one of the mistakes this ticket exists to catch, so the two must be
     * distinguishable in the very message that reports it.
     */
    case AuditIgnore = 'audit_ignore';

    /** How the origin reads in a message, before the concrete location. */
    public function label(): string
    {
        return match ($this) {
            self::ConfigIgnore => 'the ignore list',
            self::Baseline => 'the baseline',
            self::Annotation => 'a #[SqlensIgnore] annotation',
            self::AuditIgnore => 'the audit ignore list',
        };
    }
}
