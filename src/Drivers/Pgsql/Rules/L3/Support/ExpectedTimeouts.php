<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Pgsql\Rules\L3\Support;

/**
 * Which session timeouts a risky migration is expected to set before it takes a strong
 * lock — the config surface both PostgreSQL timeout-hygiene rules read.
 *
 * PostgreSQL bounds a migration's blast radius with two client settings:
 * `lock_timeout` caps how long a statement waits in the lock queue (so a blocked DDL
 * cannot pile every later query up behind it), and `statement_timeout` caps how long a
 * statement runs. A project declares which of the two it requires via
 * `sqlens.pgsql.expected_timeouts`; the two rules — {@see MissingLockTimeoutRule} and
 * the statement-timeout rule — each fire only for the one they enforce, and only when
 * that one is required. Default is both, the stricter and safer position; a project
 * that genuinely wants only one narrows the set, and a typo in it is a loud
 * misconfiguration (validated by the config schema), never a silent drop.
 *
 * The allowed names live HERE, at the driver, because they are PostgreSQL GUC names —
 * MySQL's timeout vocabulary is different and gets its own set when that driver lands.
 * The neutral config schema validates a value of this key against {@see KNOWN} through
 * a test that pins the two lists together, so core never has to name an engine setting.
 */
final readonly class ExpectedTimeouts
{
    /** The PostgreSQL lock-wait timeout GUC — caps time spent waiting in the lock queue. */
    public const string LOCK_TIMEOUT = 'lock_timeout';

    /** The PostgreSQL statement timeout GUC — caps time spent running a statement. */
    public const string STATEMENT_TIMEOUT = 'statement_timeout';

    /**
     * The timeout names a project may require — the two PostgreSQL client GUCs the
     * timeout-hygiene rules understand. A value outside this set is a config error.
     *
     * @var list<string>
     */
    public const array KNOWN = [self::LOCK_TIMEOUT, self::STATEMENT_TIMEOUT];

    /** @param  list<string>  $required  the timeout names a migration must set; only {@see KNOWN} carry meaning */
    public function __construct(public array $required) {}

    /** Both timeouts required — the shipped default, the strict and safe position. */
    public static function all(): self
    {
        return new self(self::KNOWN);
    }

    /**
     * Read the set from the raw config value, keeping only the known names. The config
     * schema has already rejected an unknown value with a named error by the time a run
     * reaches here, so this is a defensive narrowing, never the validation itself: a
     * non-list, or a value that somehow slipped through, degrades to the known subset
     * rather than letting a stray entry mean a rule silently stops enforcing.
     */
    public static function fromConfig(mixed $value): self
    {
        if (! is_array($value)) {
            return self::all();
        }

        $required = array_values(array_filter(
            $value,
            static fn (mixed $item): bool => is_string($item) && in_array($item, self::KNOWN, true),
        ));

        return new self($required);
    }

    /** Whether the named timeout is one this project requires — the per-rule gate. */
    public function requires(string $timeout): bool
    {
        return in_array($timeout, $this->required, true);
    }
}
