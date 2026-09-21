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
     * ⚠️ THIS SAID "NOT an error. The dialect-neutral core formats without one" — and the core is not
     * dialect-neutral. `SqlTokenizer` switches comment syntax on the dialect and `SqlToken` switches
     * keyword case on it, so formatting without one rewrote the file for whichever engine the guess
     * picked. `sqlens:format` refuses instead now.
     *
     * The objection it was answering is real and is answered elsewhere: a run that named its dialect
     * never reads a connection at all (see {@see DialectResolver::resolve()}), so reformatting a text
     * file still needs no database. It needs one sentence of configuration.
     */
    public static function unknown(): self
    {
        return new self(null, 'format_dialect_unknown', 'no connection named a driver, so the '
            .'dialect could not be resolved. Name it with --dialect=pgsql, --dialect=mysql, or in '
            .'sqlens.format.dialect — it is not guessed, because comment syntax and keyword case '
            .'differ per dialect and a guess rewrites the file for the wrong engine.');
    }
}
