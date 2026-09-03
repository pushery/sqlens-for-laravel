<?php

declare(strict_types=1);

namespace Pushery\SQLens\Deploy;

/**
 * What a run is allowed to do with the debt account.
 *
 * The default is {@see self::Check} and that is the whole design: `sqlens:lint` is side-effect free
 * unless somebody asks for a write. A tool that quietly edited a committed file during an ordinary
 * lint would put its own opinion into version control without anyone choosing it — and the first
 * anybody heard of it would be a diff they did not make.
 *
 * Two values rather than a boolean, because a boolean would be named `$record` and read as "should
 * I write?" at every call site. The question a caller actually asks is "what am I allowed to do
 * here", and the fast path answers neither yes nor no to that: it is a view of one file, which
 * cannot decide whether a debt exists at all.
 */
enum DebtMode: string
{
    /** Compare and report the differences. Writes nothing. */
    case Check = 'check';

    /** Compare, report, and write the reconciled ledger back. */
    case Record = 'record';

    /**
     * The mode a flag value names, or null when it names none.
     *
     * Null rather than a fallback to {@see self::Check}: a value this build does not know is almost
     * always a typo or a rename, and silently doing the safe thing means the operator believes they
     * asked for a recording run and got a checking one. The caller turns this into a named
     * configuration error listing what IS accepted.
     */
    public static function tryParse(string $value): ?self
    {
        return self::tryFrom(strtolower(trim($value)));
    }

    /** Every accepted spelling, for the message that refuses a wrong one. */
    public static function accepted(): string
    {
        return implode(', ', array_map(static fn (self $mode): string => $mode->value, self::cases()));
    }
}
