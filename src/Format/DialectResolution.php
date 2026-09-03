<?php

declare(strict_types=1);

namespace Pushery\SQLens\Format;

/**
 * What `dialect=auto` resolved to — a dialect, or a NAMED reason there is none.
 *
 * Three outcomes rather than a nullable enum, because the two absences mean opposite things and lead
 * to opposite behavior:
 *
 * - **unsupported** — the connection names an engine this package has declared a non-goal. Mapping
 *   it onto the nearest dialect would produce advice about another product, confidently.
 * - **unknown** — there is no connection to ask, or it names no driver. That is not an error at all:
 *   `sqlens:format` with no database is the north-star this suite is built around, and the
 *   dialect-neutral core formats perfectly well without one.
 */
final readonly class DialectResolution
{
    private function __construct(
        public ?Dialect $dialect,
        public ?string $reason,
        public ?string $detail,
    ) {}

    public static function of(Dialect $dialect): self
    {
        return new self($dialect, null, null);
    }

    /** An engine this package has declared a non-goal — named, never mapped onto a neighbor. */
    public static function unsupported(string $driver): self
    {
        return new self(null, 'format_dialect_unsupported', sprintf(
            'the connection uses `%s`, which this package supports on no suite. Every rule here '
            .'reasons about PostgreSQL 18+ or MySQL 8.4 semantics, and applying them to another '
            .'engine would produce advice that is confident, specific, and about a different '
            .'product. Name the dialect explicitly if you format SQL for one of the two.',
            $driver,
        ));
    }

    /**
     * No connection to ask.
     *
     * NOT an error. The dialect-neutral core formats without one, and a run that refused here would
     * make `sqlens:format` need a database to reformat a text file.
     */
    public static function unknown(): self
    {
        return new self(null, 'format_dialect_unknown', 'no connection named a driver, so the '
            .'dialect could not be resolved. A dialect-neutral backend formats anyway; name '
            .'--dialect if you want a dialect-specific one.');
    }
}
