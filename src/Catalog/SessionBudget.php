<?php

declare(strict_types=1);

namespace Pushery\SQLens\Catalog;

use Pushery\SQLens\Exceptions\InvalidSessionBudget;

/**
 * The bounds a catalog reader puts on its OWN session before it reads anything.
 *
 * Every value is required and every timeout must be positive. Zero is not "no limit" here, it is
 * refused: on PostgreSQL and MySQL alike, zero means *wait forever*, which is precisely the harm
 * these settings exist to prevent. A reader that ran unbounded against a busy production database
 * would be the incident it was sent to look for.
 *
 * The application name is required for a reason that only shows up at three in the morning: an
 * unidentified session holding a connection on production is a session somebody eventually kills
 * blind. A reader that names itself in the server's activity view can be understood instead.
 */
final readonly class SessionBudget
{
    /**
     * The default whole-reading budget, in milliseconds.
     *
     * Five seconds, and deliberately generous: this is the coarse upper bound, not the regression
     * brake. The QUERY COUNT is what catches an N+1 catalog read, because it is a property of the
     * code rather than of the machine — and a wall-clock number tight enough to catch a regression
     * would go red on a loaded laptop and be turned off within a week.
     */
    public const int DEFAULT_READ_BUDGET_MS = 5000;

    /**
     * The per-session bounds a project gets when it has not stated one.
     *
     * They exist as constants rather than only as literals in `config/sqlens.php` because a
     * published config is a FROZEN COPY: the moment a consuming app runs `vendor:publish`, its
     * file stops tracking this package, and a key added or defaulted here afterwards never
     * reaches it. Something has to answer for an absent key, and "whatever the shipped config
     * file says" is not available at that point — the reader has the app's copy, not ours.
     *
     * `SessionBudgetDefaultsTest` pins these against the shipped config file, so the two cannot
     * drift into disagreeing about what an unconfigured project gets.
     */
    public const int DEFAULT_STATEMENT_TIMEOUT_MS = 5000;

    public const int DEFAULT_LOCK_TIMEOUT_MS = 1000;

    public const int DEFAULT_IDLE_IN_TRANSACTION_TIMEOUT_MS = 5000;

    public const string DEFAULT_APPLICATION_NAME = 'sqlens';

    private function __construct(
        public int $statementTimeoutMs,
        public int $lockTimeoutMs,
        public int $idleInTransactionTimeoutMs,
        public string $applicationName,
        /**
         * How long a whole catalog reading may take before it says so.
         *
         * Distinct from the statement timeout, and not a substitute for it: a hundred fast queries
         * can be well inside every per-statement bound and still hold a production connection for
         * half a minute. Exceeding it is a NAMED undetermined rather than an abort — the objects
         * already read are worth having, and killing the run would throw them away to report a
         * problem the run itself caused.
         */
        public int $readBudgetMs = self::DEFAULT_READ_BUDGET_MS,
    ) {}

    /**
     * The same budget, tightened to a shorter one the CALLER owns.
     *
     * The deploy suite's reason for existing: a `predeploy` run promises a bounded turnaround, and
     * the audit budget is deliberately generous — five seconds for the whole reading, because it is
     * a coarse upper bound rather than a regression brake. Handing the deploy readers that same
     * number would make the gate's own promise unenforceable, and it would break QUIETLY: the run
     * would simply take longer than the number written in the documentation.
     *
     * Only ever tightens. A caller asking for MORE than the audit budget gets the audit budget,
     * because that one is the operator's statement about what this package may cost their server —
     * and a request traveling in from a config file must not be able to widen it.
     *
     * The statement timeout is narrowed alongside the reading budget, because a single statement
     * allowed to run longer than the whole reading is a bound that cannot be reached.
     */
    public function narrowedTo(int $milliseconds): self
    {
        if ($milliseconds <= 0 || $milliseconds >= $this->readBudgetMs) {
            return $this;
        }

        return new self(
            min($this->statementTimeoutMs, $milliseconds),
            $this->lockTimeoutMs,
            $this->idleInTransactionTimeoutMs,
            $this->applicationName,
            $milliseconds,
        );
    }

    public static function of(
        int $statementTimeoutMs,
        int $lockTimeoutMs,
        int $idleInTransactionTimeoutMs,
        string $applicationName,
        int $readBudgetMs = self::DEFAULT_READ_BUDGET_MS,
    ): self {
        foreach ([
            'statement_timeout' => $statementTimeoutMs,
            'lock_timeout' => $lockTimeoutMs,
            'idle_in_transaction_timeout' => $idleInTransactionTimeoutMs,
            'budget_ms' => $readBudgetMs,
        ] as $key => $value) {
            if ($value <= 0) {
                throw new InvalidSessionBudget(sprintf(
                    'catalog.%s must be a positive number of milliseconds; %d would mean "wait forever", '
                    .'which is the harm this budget exists to prevent.',
                    $key === 'budget_ms' ? $key : 'session.'.$key,
                    $value,
                ));
            }
        }

        if (trim($applicationName) === '') {
            throw new InvalidSessionBudget(
                'catalog.session.application_name must name the reader in the server\'s activity view. An '
                .'unidentified session holding a connection on production is one somebody eventually kills blind.',
            );
        }

        return new self($statementTimeoutMs, $lockTimeoutMs, $idleInTransactionTimeoutMs, $applicationName, $readBudgetMs);
    }
}
