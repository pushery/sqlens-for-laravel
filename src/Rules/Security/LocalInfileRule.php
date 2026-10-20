<?php

declare(strict_types=1);

namespace Pushery\SQLens\Rules\Security;

use Override;
use Pushery\SQLens\Levels\Level;
use Pushery\SQLens\Rules\Settings\ServerSettingExpectation;
use Pushery\SQLens\Severity\Severity;
use Pushery\SQLens\Subjects\SchemaObject;

/**
 * `local_infile` is on — the server accepts `LOAD DATA LOCAL`, which reads a file off the CLIENT.
 *
 * The direction is what makes this worth reporting, and it is the opposite of what the name suggests.
 * `LOAD DATA LOCAL INFILE` does not read a file on the server: the server sends the client a request
 * naming a path, and a compliant client reads that file off its own disk and uploads it. The client
 * decides nothing about which path — it is told.
 *
 * What this setting governs is whether the server takes such a statement at all. With it on, a
 * statement injected into the application's connection can name `/etc/passwd`, an `.env` or a key
 * file on the APPLICATION host and load it into a table, provided the client allows LOCAL. The
 * application need not run a single `LOAD DATA` statement of its own for this to happen.
 *
 * A hostile server is a different case, and not this setting's: such a server can ask for a file
 * whatever its own variable says, and only the client's refusal stops it.
 *
 * ## Why `medium`
 *
 * It needs an injected statement and a client that allows LOCAL, which is a bigger precondition
 * than most findings in this suite carry. What it does not need is the FILE privilege: the client
 * reads with its own file access, so no grant on the server stands in the way.
 *
 * ## The honesty limit
 *
 * This reads the SERVER's side of the negotiation. A client can refuse independently — PHP's
 * `mysqli.allow_local_infile` and PDO's `Pdo\Mysql::ATTR_LOCAL_INFILE` both default to off on
 * current builds — and this rule cannot see that. It reports that the server would ask, not that
 * anybody would answer.
 */
final class LocalInfileRule extends AbstractSettingSecurityRule
{
    public function id(): string
    {
        return 'SEC.CFG.LOCAL_INFILE';
    }

    public function level(): Level
    {
        return Level::Capturable;
    }

    #[Override]
    public function severity(): Severity
    {
        return Severity::Medium;
    }

    public function settingDriver(): string
    {
        return 'mysql';
    }

    public function settingVariable(): string
    {
        return 'local_infile';
    }

    protected function violation(string $serverValue, ServerSettingExpectation $expectation, SchemaObject $object): ?string
    {
        // Case-folded and trimmed: MySQL answers `ON`/`OFF` here, but the value travels through a
        // config file that accepts `1`/`0` and `on`/`off`, and flagging a spelling would be a pure
        // false positive. `1` is the same state as `ON` and is treated as one.
        $value = strtoupper(trim($serverValue));

        if ($value !== 'ON' && $value !== '1') {
            return null;
        }

        return sprintf(
            'local_infile is %s, so this server accepts LOAD DATA LOCAL INFILE, and the direction is '
            .'the opposite of what the name suggests: the statement does not read a file on the '
            .'server. The server sends the client a request naming a path, and a compliant client '
            .'reads that path off its OWN disk and uploads it. The client does not choose the path, '
            .'it is told one. With the setting on, a statement injected into the application\'s '
            .'connection can therefore load an .env or a key file from the APPLICATION host into a '
            .'table, without the application running any LOAD DATA statement of its own. The FILE '
            .'privilege is not involved: the client reads with its own file access. A hostile server '
            .'is a different case, one a client\'s refusal answers and this setting does not. This '
            .'reads the SERVER\'s side only — a client can refuse independently, and current PHP '
            .'builds do by default, which this rule cannot see. %s',
            $serverValue,
            $this->remediation($expectation),
        );
    }

    /**
     * @return list<string>
     */
    #[Override]
    public function limitations(): array
    {
        return [
            'reads the GLOBAL value, not the file: a setting changed on disk and not yet reloaded is invisible here, and a value set for one session is never read',
            'judges the server\'s willingness, not any client\'s use of it. `local_infile` on with no client that asks for it exposes nothing today; it is the client somebody adds later that this exists to get ahead of',
        ];
    }
}
