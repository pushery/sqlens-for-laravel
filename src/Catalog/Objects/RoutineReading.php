<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Catalog\CatalogCompleteness;
use Pushery\SQLens\Catalog\CatalogSkip;

/**
 * The stored routines in scope, or the named reason there are none.
 *
 * Modeled on {@see HbaReading} and {@see RlsReading}, because it has to tell apart the same states —
 * and here all four genuinely occur:
 *
 * - **read** — the routines, sorted by identity so two runs over an unchanged server agree.
 * - **partial** — some came back and something was withheld. Distinct from empty: a rule that could
 *   not tell those apart would report a database with no `SECURITY DEFINER` routines when what
 *   actually happened is that nobody was allowed to look at half of them.
 * - **refused** — the catalog answered nothing. It has no factory of its own here, unlike
 *   {@see HbaReading::refused()}, and that is deliberate rather than an omission: refused IS
 *   `partial([], $skips)` — the same object, down to the field — and neither reader can produce it
 *   any other way, because `attempt()` already answers with an empty list and a recorded skip when a
 *   read fails. A second name for one object would be a factory with no caller, which is a promise
 *   nobody keeps. `HbaReading` keeps its own because `pg_hba_file_rules` genuinely refuses `42501`
 *   and its reader returns early on that path.
 * - **complete and empty** — a real and unremarkable answer: most schemas have no stored routines at
 *   all, and that is not a finding.
 *
 * The last two are why `supported` exists as a flag on the READING: it lets the rules stay silent on
 * an engine without the concept, without any of them containing a driver check.
 */
final readonly class RoutineReading
{
    /**
     * @param  list<RoutineObject>  $routines  sorted by identity
     * @param  list<CatalogSkip>  $skips
     */
    private function __construct(
        public array $routines,
        public CatalogCompleteness $completeness,
        public array $skips,
        public bool $supported,
    ) {}

    /**
     * @param  list<RoutineObject>  $routines
     */
    public static function complete(array $routines): self
    {
        return new self(self::ordered($routines), CatalogCompleteness::Complete, [], true);
    }

    /**
     * @param  list<RoutineObject>  $routines
     * @param  non-empty-list<CatalogSkip>  $skips
     */
    public static function partial(array $routines, array $skips): self
    {
        return new self(self::ordered($routines), CatalogCompleteness::Partial, $skips, true);
    }

    /** An engine with no stored routines at all: nothing to read and nothing to say. */
    public static function unsupported(): self
    {
        return new self([], CatalogCompleteness::Complete, [], false);
    }

    public function isComplete(): bool
    {
        return $this->completeness === CatalogCompleteness::Complete;
    }

    /**
     * @param  list<RoutineObject>  $routines
     * @return list<RoutineObject>
     */
    private static function ordered(array $routines): array
    {
        usort($routines, static fn (RoutineObject $a, RoutineObject $b): int => $a->identity() <=> $b->identity());

        return $routines;
    }
}
