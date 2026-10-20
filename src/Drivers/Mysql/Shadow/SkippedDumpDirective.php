<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Shadow;

/**
 * A statement from a `schema:dump` that is a client directive, not schema SQL, and
 * is therefore not replayed into the shadow database — recorded on the
 * {@see SchemaDumpPlan} rather than silently swallowed.
 *
 * A version-gated conditional comment such as `/*!40101 SET NAMES … *​/` sets
 * client session state (character set, collation, SQL mode) that the shadow
 * database has no need of; replaying it would at best be a no-op and at worst fail.
 * One that builds nothing of the dumped schema, such as a `DROP DATABASE`, is
 * skipped the same way, with a reason of its own.
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

    /**
     * What a person reading the run should know about this directive, or null when leaving it out
     * changes nothing the shadow database keeps.
     *
     * A directive that sets the SQL mode or the time zone to a value does: the dump's statements ran
     * under the shadow session's own setting instead, and a routine or trigger keeps the SQL mode it
     * was created under. The replay sets the foreign-key and unique checks itself, and a character
     * set or a saved variable changes nothing the shadow keeps.
     */
    public function note(): ?string
    {
        if (preg_match('/\b(sql_mode|time_zone)\s*=\s*\'/i', $this->directive, $setting) !== 1) {
            return null;
        }

        return sprintf(
            'The schema dump\'s %s was not replayed (%s), so the dump\'s statements ran under the shadow session\'s own %s.',
            $this->directive,
            $this->reason,
            strtolower($setting[1]),
        );
    }
}
