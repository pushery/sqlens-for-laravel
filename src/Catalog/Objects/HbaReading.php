<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog\Objects;

use Pushery\SQLens\Catalog\CatalogCompleteness;
use Pushery\SQLens\Catalog\CatalogSkip;

/**
 * The host-based authentication rules a server is running, or the named reason there are none.
 *
 * Modeled on {@see RlsReading} rather than invented, because the three states it has to tell apart
 * are the same three:
 *
 * - **read** — the rules, in file order.
 * - **refused** — `pg_hba_file_rules` is a VIEW over a superuser-only FUNCTION, and `pg_read_all_settings` is NOT enough to read it — measured on PostgreSQL 18.4: a role holding `pg_read_all_settings` gets `permission denied for function pg_hba_file_rules`, and `has_function_privilege` says `f`. Only superuser, or a role that has been granted EXECUTE on that function explicitly (`GRANT EXECUTE ON FUNCTION pg_hba_file_rules() TO …`, measured: 6 rows afterwards). On a managed instance the
 *   refusal is therefore the NORMAL case rather than a fault, and an empty list would report a
 *   server that lets nobody in, which is both alarming and false.
 * - **unsupported** — MySQL has no `pg_hba.conf` and nothing shaped like it. Its access control is
 *   the account's own host pattern, which this package already reads as part of the account. Telling
 *   a MySQL project its HBA rules could not be read would send it looking for a file its server does
 *   not have, and an `undetermined` on every run is the noise that gets a suite switched off.
 *
 * The third state is why `supported` is a flag on the READING and not a driver check inside each of
 * the five HBA rules: the security family is engine-neutral by data, so "this rule is silent on that
 * engine" is a property of what the reader returned rather than a line somebody has to remember to
 * write five times.
 */
final readonly class HbaReading
{
    /**
     * @param  list<HbaRule>  $rules  in file order — which IS their evaluation order
     * @param  list<CatalogSkip>  $skips
     */
    private function __construct(
        public array $rules,
        public CatalogCompleteness $completeness,
        public array $skips,
        public bool $supported,
    ) {}

    /**
     * @param  list<HbaRule>  $rules
     */
    public static function complete(array $rules): self
    {
        return new self(self::ordered($rules), CatalogCompleteness::Complete, [], true);
    }

    /**
     * @param  list<HbaRule>  $rules
     * @param  non-empty-list<CatalogSkip>  $skips
     */
    public static function partial(array $rules, array $skips): self
    {
        return new self(self::ordered($rules), CatalogCompleteness::Partial, $skips, true);
    }

    /**
     * The view refused, so nothing is claimed about how this server authenticates.
     *
     * Partial with no rules rather than complete with none: something WAS withheld, and a reader who
     * cannot tell those apart would take silence for a clean bill of health — which is the one
     * reading this package must never produce.
     *
     * @param  non-empty-list<CatalogSkip>  $skips
     */
    public static function refused(array $skips): self
    {
        return new self([], CatalogCompleteness::Partial, $skips, true);
    }

    /**
     * The engine has no host-based authentication file, so there is nothing to read and nothing to say.
     *
     * The difference from {@see self::refused()} is the whole reason it exists: that one means "ask
     * somebody with more rights", this one means "the question does not apply here".
     */
    public static function unsupported(): self
    {
        return new self([], CatalogCompleteness::Complete, [], false);
    }

    public function isComplete(): bool
    {
        return $this->completeness === CatalogCompleteness::Complete;
    }

    /**
     * @param  list<HbaRule>  $rules
     * @return list<HbaRule>
     */
    private static function ordered(array $rules): array
    {
        // File order, because pg_hba is evaluated first-match-wins: a rule's position is part of what
        // it means, and sorting by anything else would make a finding about "the rule above this one"
        // impossible to state.
        usort($rules, static fn (HbaRule $a, HbaRule $b): int => $a->ruleNumber <=> $b->ruleNumber);

        return $rules;
    }
}
