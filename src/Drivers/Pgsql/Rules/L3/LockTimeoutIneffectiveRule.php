<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3;

use Pushery\SQLens\Categories\Category;
use Pushery\SQLens\Drivers\Pgsql\Catalog\PgsqlSettingCrossFactCollector;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\AbstractServerSettingRule;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * A `lock_timeout` that is not smaller than `statement_timeout` can never fire.
 *
 * ## The two clocks measure different things, and one of them can swallow the other
 *
 * `lock_timeout` bounds the wait in the lock QUEUE. `statement_timeout` bounds the whole statement,
 * queue included. Set the second to a number the first cannot reach — equal is already too large —
 * and the statement is aborted before the lock wait ever gets to its own limit. The lock clock is
 * then configured, visible, and dead.
 *
 * The configuration reads like a safety net and is none. Worse, the failure afterwards is
 * MISLABELED: the statement comes back as a statement timeout, so whoever reads the log concludes
 * the DDL itself is slow and goes looking at the table, when what actually happened is that the
 * migration never got the lock.
 *
 * ## Why this package cares more than most
 *
 * Its own remediation preamble recommends both clocks and justifies them by exactly this
 * difference — the wait in the queue versus the run afterwards. A rule that recommends a pair and
 * cannot see when the pair is wrong is advice that stops being true the moment somebody follows it
 * with the wrong numbers. An arm proves the shipped template never produces such a pair.
 *
 * ## Two states this deliberately does NOT report
 *
 * `lock_timeout = 0` is the existing finding of `PG.L3.MISSING_LOCK_TIMEOUT` — unbounded, not
 * ineffective — and reporting it here as well would be two findings for one fact, which is how a
 * report stops being read. `statement_timeout = 0` means there is no statement clock to abort
 * first, so a lock clock of any size can fire; that is the arrangement working, not a defect.
 *
 * ## What "effective" means here, and why it is not the session value
 *
 * `reset_val`, which is what the configuration file, the database and the role have settled between
 * them: the pair a deploy session inherits before it sets anything of its own. NOT `setting` — this
 * audit sets both of these timeouts on its own session before reading anything, so the session
 * value describes SQLens on every server it is ever pointed at. Which layer named either clock is
 * measured beside it, from `pg_db_role_setting`, because a reader told the pair is wrong still has
 * to know which of three change paths to take.
 *
 * ## MySQL gets no twin, and the reason is not symmetry
 *
 * `max_execution_time` applies to read-only SELECTs only, so it cannot abort the DDL this is about.
 * `lock_wait_timeout` (metadata locks) and `innodb_lock_wait_timeout` (row locks) are two separate
 * clocks with separate reach, and neither is nested inside an overall statement clock the way these
 * two are. The pairing is not the same shape, so a rule with this id over there would be a
 * different claim wearing the same name.
 */
final class LockTimeoutIneffectiveRule extends AbstractServerSettingRule
{
    public function id(): string
    {
        return 'PG.L3.LOCK_TIMEOUT_INEFFECTIVE';
    }

    /**
     * Lock hygiene, like the two rules it sits beside.
     *
     * The level names the SUBJECT, not the mechanism: this is read from the catalog rather than from
     * a migration, and it is still a statement about whether a lock wait is bounded — which is what
     * level 3 is for. Filing it under the level of the machinery that reads it would scatter one
     * question across two gates.
     */
    public function level(): Level
    {
        return Level::LockHygiene;
    }

    public function category(): Category
    {
        return Category::Safety;
    }

    public function settingDriver(): string
    {
        return 'pgsql';
    }

    public function settingVariable(): string
    {
        return 'lock_timeout';
    }

    /**
     * Judged from the RELATION between two values, so no matrix entry could hold the expectation.
     *
     * A shipped file can say `lock_timeout` should be non-zero. It cannot say it should be smaller
     * than another setting, because the answer depends on that other setting's value on this
     * instance. This rule supplies the missing fact, which is what the base's docblock describes as
     * the sanctioned reason to override the matrix rather than a weakening of it.
     */
    protected function bringsOwnExpectation(): bool
    {
        return true;
    }

    /**
     * Both halves, declared — so a read that failed reports `undetermined` with its reason instead
     * of going quiet. Silence here would be indistinguishable from a healthy pair.
     *
     * @return list<string>
     */
    protected function requiredCrossFacts(): array
    {
        return [
            PgsqlSettingCrossFactCollector::STATEMENT_TIMEOUT,
            PgsqlSettingCrossFactCollector::TIMEOUT_OVERRIDES,
        ];
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        $lock = $this->milliseconds($serverValue);
        $statement = $this->milliseconds(
            $this->crossFact($object, PgsqlSettingCrossFactCollector::STATEMENT_TIMEOUT) ?? '0',
        );

        // Unbounded is the OTHER rule's finding, and there is no statement clock to be swallowed by
        // when the second is zero. Neither is this rule's subject.
        if ($lock === 0 || $statement === 0 || $lock < $statement) {
            return null;
        }

        return sprintf(
            'lock_timeout is %d ms and statement_timeout is %d ms, so the lock clock can never '
            .'fire: the statement is aborted at %d ms with the lock wait still inside it, and the '
            .'wait never reaches its own limit. The two bound different things — lock_timeout the '
            .'wait in the QUEUE, statement_timeout the whole statement including that wait — and '
            .'with this pair the first is configured, visible and dead. The failure afterwards is '
            .'mislabeled as well: the statement returns a statement timeout, so a reader concludes '
            .'the DDL is slow and goes looking at the table, when the migration never got the lock '
            .'at all. Set lock_timeout strictly below statement_timeout, leaving room for the work '
            .'itself. %s These are the values a fresh session inherits (reset_val), not this '
            .'audit session\'s own — SQLens sets both on itself before reading anything.',
            $lock,
            $statement,
            $statement,
            $this->whereToChangeIt($object),
        );
    }

    /**
     * Which layer to change, named from what was measured rather than guessed.
     *
     * An empty measurement is a real answer and the commonest one: neither clock was set by
     * `ALTER DATABASE` or `ALTER ROLE`, so the pair came from the configuration file or the
     * built-in default.
     */
    private function whereToChangeIt(SchemaObject $object): string
    {
        $overrides = $this->crossFact($object, PgsqlSettingCrossFactCollector::TIMEOUT_OVERRIDES) ?? '';

        if (trim($overrides) === '') {
            return 'Neither clock is set by ALTER DATABASE or ALTER ROLE, so this pair comes from '
                .'postgresql.conf or the built-in default; change it there, or per deploy in the '
                .'migration preamble.';
        }

        return sprintf('Set by: %s — change it at that level rather than in postgresql.conf.', $overrides);
    }

    /**
     * A timeout as whole milliseconds.
     *
     * `pg_settings` reports both of these in milliseconds already, with no unit suffix, so this is a
     * cast rather than a parser. It is a method anyway because the two call sites must not drift
     * about what a non-numeric value means: zero, which routes into the "not this rule's subject"
     * arm above rather than into a comparison against a number nobody read.
     */
    private function milliseconds(string $value): int
    {
        $trimmed = trim($value);

        return is_numeric($trimmed) ? (int) $trimmed : 0;
    }
}
