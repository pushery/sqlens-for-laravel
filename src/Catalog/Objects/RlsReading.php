<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Catalog\CatalogCompleteness;
use Pushery\SQLens\Catalog\CatalogSkip;

/**
 * The RLS state of the tables a project asked about — and, when it asked about none, the fact that it
 * did not.
 *
 * ## Why an unconfigured project gets nothing rather than everything
 *
 * "Which tables hold tenant data" is a question only the project can answer. Reading every table and
 * reporting the ones without RLS would produce a finding for every reference table, every job queue
 * and every migration ledger in the schema — a report nobody finishes reading, from a tool that has
 * learned nothing about the application.
 *
 * So the reading is EMPTY and says why, and the rules turn that into one `undetermined` naming the
 * config key. A project that answers the question gets checks; one that does not gets told what to
 * set, once.
 */
final readonly class RlsReading
{
    /**
     * @param  list<RlsState>  $states  sorted by table
     * @param  list<CatalogSkip>  $skips
     */
    private function __construct(
        public array $states,
        public CatalogCompleteness $completeness,
        public array $skips,
        /** Whether the project told SQLens which tables to look at. False ⇒ nothing was judged. */
        public bool $configured,
        /**
         * Whether the ENGINE has row-level security at all.
         *
         * Kept apart from `configured` because the two produce opposite reports. MySQL 8.4 has no RLS:
         * telling a MySQL project to set `security.rls.tables` would send it looking for a feature its
         * server does not have, and an `undetermined` on every run is the noise that gets a suite
         * switched off. A PostgreSQL project that configured nothing gets exactly that `undetermined`,
         * once, naming the key.
         *
         * A flag on the reading rather than a driver check inside each rule: the security family is
         * engine-neutral by DATA, so "this rule is silent on that engine" is a property of what the
         * reader returned instead of a line somebody has to remember to write in four rules.
         */
        public bool $supported,
    ) {}

    /**
     * @param  list<RlsState>  $states
     */
    public static function complete(array $states): self
    {
        return new self(self::sorted($states), CatalogCompleteness::Complete, [], true, true);
    }

    /**
     * @param  list<RlsState>  $states
     * @param  non-empty-list<CatalogSkip>  $skips
     */
    public static function partial(array $states, array $skips): self
    {
        return new self(self::sorted($states), CatalogCompleteness::Partial, $skips, true, true);
    }

    /**
     * The project named no tables, so nothing was read and nothing is claimed.
     *
     * Complete rather than partial on purpose: nothing was withheld and nothing failed — the question
     * was never asked. A `partial` here would send a reader looking for a privilege problem that does
     * not exist.
     */
    public static function unconfigured(): self
    {
        return new self([], CatalogCompleteness::Complete, [], false, true);
    }

    /**
     * The engine has no row-level security, so there is nothing to configure and nothing to report.
     *
     * The difference from {@see self::unconfigured()} is the whole reason it exists: that one produces
     * one `undetermined` naming the config key, which is right for a PostgreSQL project that has not
     * answered the question and wrong for a MySQL one that cannot be asked it.
     */
    public static function unsupported(): self
    {
        return new self([], CatalogCompleteness::Complete, [], false, false);
    }

    public function isComplete(): bool
    {
        return $this->completeness === CatalogCompleteness::Complete;
    }

    /**
     * @param  list<RlsState>  $states
     * @return list<RlsState>
     */
    private static function sorted(array $states): array
    {
        usort($states, static fn (RlsState $a, RlsState $b): int => $a->table <=> $b->table);

        return $states;
    }
}
