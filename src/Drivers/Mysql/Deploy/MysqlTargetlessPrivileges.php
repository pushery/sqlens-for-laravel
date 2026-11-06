<?php

declare(strict_types=1);

namespace Pushery\SQLens\Drivers\Mysql\Deploy;

use Pushery\SQLens\Canonical\StatementKind;
use Pushery\SQLens\Capture\CapturedStatement;
use Pushery\SQLens\Deploy\TargetlessPrivileges;

/**
 * What MySQL asks of the migration account for the statements its classifier keeps without a
 * target.
 *
 * A session setting needs nothing when every variable it sets is one any account may set for its
 * own session, the timeouts `MY.L3.MISSING_LOCK_WAIT_TIMEOUT` asks for and the `FOREIGN_KEY_CHECKS`
 * switch Laravel writes among them, and so do `SET NAMES`, `SET CHARACTER SET`, `SET TRANSACTION`
 * and a user-defined variable. A global or persisted variable, `SET ROLE`, `SET PASSWORD` and a
 * session variable this list does not name stay unanswered rather than assumed harmless: some
 * session variables need `SESSION_VARIABLES_ADMIN` or `SYSTEM_VARIABLES_ADMIN`.
 */
final readonly class MysqlTargetlessPrivileges implements TargetlessPrivileges
{
    /** Session variables a migration has a reason to set, each settable by any account for its own session. */
    private const array SESSION_VARIABLES = [
        'autocommit', 'character_set_client', 'character_set_connection', 'character_set_results',
        'collation_connection', 'foreign_key_checks', 'group_concat_max_len', 'innodb_lock_wait_timeout',
        'lock_wait_timeout', 'max_execution_time', 'net_read_timeout', 'net_write_timeout', 'sql_mode',
        'sql_safe_updates', 'time_zone', 'transaction_isolation', 'transaction_read_only', 'unique_checks',
        'wait_timeout',
    ];

    /** One assignment of a SET: its scope, written as a word or behind `@@`, and the variable it sets. */
    private const string ASSIGNMENT = '/^(?:(GLOBAL|PERSIST|PERSIST_ONLY|SESSION|LOCAL)\s+)?(?:@@(?:(GLOBAL|PERSIST|PERSIST_ONLY|SESSION|LOCAL)\.)?)?`?([A-Za-z_][A-Za-z0-9_]*)`?\s*:?=/i';

    public function requirementsOf(CapturedStatement $statement): ?array
    {
        if ($statement->statementKind !== StatementKind::SessionSetting) {
            return null;
        }

        $setting = (string) preg_replace('/^SET\s+/i', '', trim($statement->canonicalSql ?? $statement->rawSql));

        if (preg_match('/^(?:NAMES|CHARACTER\s+SET|CHARSET|(?:SESSION\s+|LOCAL\s+)?TRANSACTION)\b/i', $setting) === 1) {
            return [];
        }

        // Split at the commas outside a quoted value, so `sql_mode = 'A,B'` stays one assignment.
        preg_match_all('/(?:\'(?:[^\'\\\\]|\\\\.)*\'|"(?:[^"\\\\]|\\\\.)*"|`[^`]*`|[^,\'"`])+/', $setting, $parts);

        foreach ($parts[0] as $assignment) {
            if (! $this->needsNothing(trim($assignment))) {
                return null;
            }
        }

        return [];
    }

    /** Whether one assignment sets a user-defined variable, or a session variable any account may set. */
    private function needsNothing(string $assignment): bool
    {
        if (preg_match('/^@[A-Za-z0-9_$.]+\s*:?=/', $assignment) === 1) {
            return true;
        }

        if (preg_match(self::ASSIGNMENT, $assignment, $variable) !== 1) {
            return false;
        }

        $scope = strtoupper($variable[1] !== '' ? $variable[1] : $variable[2]);

        return in_array($scope, ['', 'SESSION', 'LOCAL'], true) && in_array(strtolower($variable[3]), self::SESSION_VARIABLES, true);
    }
}
