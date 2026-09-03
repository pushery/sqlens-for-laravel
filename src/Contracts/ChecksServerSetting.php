<?php

declare(strict_types=1);

namespace Pushery\SQLens\Contracts;

use Pushery\SQLens\Rules\Settings\ServerSettingMatrix;

/**
 * A rule that judges one server variable against the shipped matrix — and says which one.
 *
 * ## Why the rule declares the variable instead of the test inferring it
 *
 * The matrix exists so no rule hard-codes its own expectation. That only holds if something checks
 * it, and the check needs to pair each rule with its entry. Inferring the pair from the rule id
 * would work today — `MY.L1.SQL_MODE` does contain `sql_mode` — and would be a guard that catches
 * only the mistakes somebody already thought of: a rule id that abbreviates, a variable whose name
 * appears inside another's, a rule covering a variable whose name is not id-shaped at all. Each of
 * those passes the heuristic while pairing nothing.
 *
 * So the pairing is DECLARED. A rule naming a variable the matrix does not have is then a hard
 * error rather than a silent non-match, which is the direction that matters: the failure mode this
 * whole arrangement guards against is an expectation that lives in exactly one place and is
 * therefore never compared with anything.
 *
 * ## What implementing it obliges
 *
 * That the rule's verdict comes from {@see ServerSettingMatrix}, asked with the server's version —
 * not from a literal in the rule. The matrix answers `null` for a variable it does not cover on
 * that version, and a rule reaching that answer reports that it could not check rather than
 * assuming the value is fine.
 */
interface ChecksServerSetting
{
    /**
     * The driver whose matrix entries this rule reads — `pgsql` or `mysql`.
     *
     * Explicit rather than derived from the rule set that happens to hold the rule: a rule is
     * registered by a driver pack, but nothing in the {@see Rule} contract exposes that, and a
     * consistency check that had to guess it would be checking its own guess.
     */
    public function settingDriver(): string;

    /**
     * The variable this rule judges, spelled exactly as the server reports it.
     *
     * Case matters and differs by engine — PostgreSQL's `TimeZone` against MySQL's `time_zone` —
     * because it is the key the reading is stored under, not a label.
     */
    public function settingVariable(): string;
}
